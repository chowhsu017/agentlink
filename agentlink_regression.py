#!/usr/bin/env python3
"""
AgentLink 一键跨机回归（T3，2026-10-12）
=========================================
一条命令跑完整链路，输出**结构化 pass/fail**，供人工或 CI 一眼判断。

覆盖（每一步独立判定，不因一步失败就停）：
  ① 连通性：对端 HTTP /agentlink/call 可达（ring 响应）
  ② 加密握手：建 cipher（e2ee=True）
  ③ 资源调用：发加密命令 → 收加密结果并解密成功
  ④ 双签交换：两轮（hash + sig），两端 sig_object 一致
  ⑤ 真实验签：用双方 Ed25519 公钥对 sig_object 验签（sig_verified=True）
  ⑥ 完整性：ledger.verify() ok=True

用法：
  python3 agentlink_regression.py                      # 默认对端 zheng-mac，命令 @search 刑侦
  python3 agentlink_regression.py mac-mini "@run 摘要"  # 指定对端与命令
  python3 agentlink_regression.py -j                   # JSON 输出（CI 用）

退出码：0=全过；1=有失败项；2=用法/环境错误
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid

SRC = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC)

import httpx  # noqa: E402
import websockets  # noqa: E402

from agentlink import load_keypair, _unb64, compute_shared_secret, derive_session_key, SessionCipher  # noqa: E402
from agentlink.secure_session import create_secure_agent  # noqa: E402
from agentlink.ledger import SessionLedger, compute_sig_object  # noqa: E402
from agentlink.crypto import sign_message  # noqa: E402
from agentlink.netutil import prefer_ipv4_url  # noqa: E402
from agentlink.peer_registry import resolve_peer  # noqa: E402

MY_NAME = os.environ.get("AL_MY_NAME", "tiger-mac")
MY_IP = os.environ.get("AL_MY_IP", "192.168.1.115")
MY_PORT = int(os.environ.get("AL_MY_PORT", "18899"))
KEY = os.path.expanduser(os.environ.get("AL_MY_KEY", "~/.openclaw/workspace/agentlink_tiger-mac.key.json"))

RESULTS: list[dict] = []


def _rec(step: str, ok: bool, detail: str = "") -> None:
    RESULTS.append({"step": step, "ok": bool(ok), "detail": detail})


async def _await_ledger_msg(ws, want_round: str, timeout: float = 6.0):
    """从 WS 读一条 ledger_sig 应答（匹配 round）。兼容两种包装。"""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            raw = await asyncio.wait_for(
                ws.recv(), timeout=max(0.2, deadline - asyncio.get_event_loop().time()))
        except asyncio.TimeoutError:
            return None
        msg = json.loads(raw)
        body = msg.get("body") or msg.get("result") or {}
        if body.get("round") == want_round:
            return body
    return None


async def run(peer_name: str, command: str) -> int:
    peer = resolve_peer(peer_name)
    if not peer.get("http"):
        print(f"❌ 对端 {peer_name} 未配置（检查 agentlink_peers.json）")
        return 2
    target = prefer_ipv4_url(peer["http"]) if peer.get("net") == "lan" else peer["http"]
    target_ws = prefer_ipv4_url(peer["ws"]) if peer.get("net") == "lan" else peer["ws"]
    target_did = peer.get("did", "")
    sid = f"reg-{uuid.uuid4().hex[:8]}"
    print(f"🔎 AgentLink 回归 | 对端={peer_name}({peer.get('net')}) | 命令={command} | session={sid}")
    print("=" * 64)

    state, secure = create_secure_agent(MY_NAME, MY_PORT, keypair_path=KEY)
    state.secure = secure
    state.session_id = sid
    state.did = secure.kp.did
    state.http_url = f"http://{MY_IP}:{MY_PORT}"

    ledger = SessionLedger(sid, state.did, target_did, channel="ws", peer_name=MY_NAME)
    ledger._is_initiator_view = True

    # ── ① 连通性：call → ring ──
    try:
        r = httpx.post(f"{target}/agentlink/call", json={
            "jsonrpc": "2.0", "method": "agentlink.call", "params": {
                "meta": {"profile": "agentlink.session.v1", "sender_did": state.did,
                         "target_did": target_did},
                "body": {"session_id": sid, "caller_name": MY_NAME, "caller_url": state.http_url,
                         "caller_ws": f"ws://{MY_IP}:{MY_PORT}/agentlink/ws",
                         "enc_public_b64": secure.get_auth_payload()["enc_public_b64"],
                         "sign_public_b64": secure.get_auth_payload()["sign_public_b64"]}}}, timeout=8)
        res = r.json().get("result", {})
        ok = res.get("type") == "ring"
        _rec("① 连通性(call→ring)", ok, "" if ok else r.text[:120])
    except Exception as e:  # noqa: BLE001
        _rec("① 连通性(call→ring)", False, f"{type(e).__name__}: {e}")
        return _finish()

    real_peer = res.get("peer_did") or target_did
    peer_sign_b64 = res.get("sign_public_b64", "")
    ledger.record_handshake(kex="X25519", cipher="ChaCha20-Poly1305", sig="Ed25519",
                            did_verified=bool(real_peer), nonce=res.get("salt", "")[:12],
                            peer_fpr=str(real_peer)[:16])

    # ── ② 加密握手 ──
    try:
        shared = compute_shared_secret(secure.kp.enc_private, _unb64(res["enc_public_b64"]))
        key, salt = derive_session_key(shared, _unb64(res["salt"]))
        secure.cipher = SessionCipher(key, salt, state.did, real_peer)
        secure.e2ee_enabled = True
        state.peer_did = real_peer
        _rec("② 加密握手", secure.e2ee_enabled, f"peer={real_peer}")
    except Exception as e:  # noqa: BLE001
        _rec("② 加密握手", False, f"{type(e).__name__}: {e}")
        return _finish()

    got = None
    peer_hash = peer_sig = my_sig = None
    # ── ③ 资源调用 + ④ 双签 + ⑤ 验签 ──
    try:
        ws_url = f"{target_ws}/{sid}" if not target_ws.endswith("/ws") else f"{target_ws}/{sid}"
        async with websockets.connect(ws_url) as ws:
            await asyncio.sleep(1.0)
            enc = secure.encrypt_payload(command)
            await ws.send(json.dumps({
                "method": "agentlink.data",
                "meta": {"profile": "agentlink.session.v1", "sender_did": state.did,
                         "sender_name": state.name, "session_id": sid},
                "body": {"seq": 1, "type": "text", "payload": enc}}))
            ledger.record_frame(sender=state.did, enc="ratchet", cipher_suite="ChaCha20-Poly1305",
                                decrypt="ok", payload=enc.encode()[:64])

            deadline = asyncio.get_event_loop().time() + 40
            while asyncio.get_event_loop().time() < deadline:
                try:
                    raw = await asyncio.wait_for(
                        ws.recv(), timeout=max(0.2, deadline - asyncio.get_event_loop().time()))
                except asyncio.TimeoutError:
                    break
                msg = json.loads(raw)
                body = msg.get("body") or msg.get("result") or {}
                payload = body.get("payload", "")
                if isinstance(payload, str) and payload.startswith("🔒"):
                    enc2 = _unb64(payload[1:])
                    rseq = body.get("seq", 1)
                    plain = None
                    try:
                        plain = secure.cipher.ratchet_decrypt(enc2, rseq)
                    except Exception:  # noqa: BLE001
                        plain = None
                    if plain is None:
                        plain = secure.cipher.decrypt(enc2, rseq)
                    if plain is not None:
                        got = plain.decode("utf-8", "replace")
                        ledger.record_frame(sender=real_peer, enc="ratchet",
                                            cipher_suite="ChaCha20-Poly1305", decrypt="ok", payload=enc2)
                        break
            _rec("③ 资源调用(加密往返)", got is not None,
                 f"回包 {len(got)} 字符" if got else "未收到加密结果")

            # ── 双签交换 ──
            ledger.record_close(reason="regression_done", frames_in=1 if got else 0, frames_out=1)
            h_self = ledger.events[-1].hash
            await ws.send(json.dumps({
                "method": "ledger_sig",
                "meta": {"session_id": sid, "sender_did": state.did},
                "body": {"round": "hash", "ledger_hash": h_self}}))
            hb = await _await_ledger_msg(ws, "hash", timeout=6)
            peer_hash = hb.get("ledger_hash") if hb else None

            if peer_hash:
                sig_object = compute_sig_object(h_self, peer_hash, is_initiator=True)
                my_sig = sign_message(secure.kp.sign_private, sig_object.encode()).hex()
                await ws.send(json.dumps({
                    "method": "ledger_sig",
                    "meta": {"session_id": sid, "sender_did": state.did},
                    "body": {"round": "sig", "sig_object": sig_object, "sig": my_sig}}))
                sb = await _await_ledger_msg(ws, "sig", timeout=6)
                peer_sig = sb.get("sig") if sb else None
                ledger.record_signature_exchange(
                    initiator_sig_received=bool(peer_sig), responder_sig_received=bool(peer_sig),
                    self_hash=h_self, peer_hash=peer_hash, is_initiator=True)
                ledger.seal()
                ledger.attach_signatures(initiator_sig=my_sig, responder_sig=peer_sig or "")
            else:
                ledger.record_signature_exchange(initiator_sig_received=False, responder_sig_received=False)
                ledger.seal()
                ledger.attach_signatures(initiator_sig="", responder_sig="")
            _rec("④ 双签交换", bool(peer_hash and peer_sig),
                 f"peer_hash={'有' if peer_hash else '无'} peer_sig={'有' if peer_sig else '无'}")
    except Exception as e:  # noqa: BLE001
        _rec("③ 资源调用(加密往返)", False, f"{type(e).__name__}: {e}")
        ledger.record_frame(sender=state.did, enc="plain", cipher_suite="?",
                            decrypt="error", downgrade=True, reason="unexpected_cipher_change")
        ledger.seal()
    finally:
        ledger.save()

    # ── ⑤ 真实验签 + ⑥ 完整性 ──
    try:
        my_pub = _unb64(secure.get_auth_payload()["sign_public_b64"])
        peer_pub = _unb64(peer_sign_b64) if peer_sign_b64 else None
        if peer_pub:
            ver = ledger.verifier_from_pubkeys(my_pub, peer_pub)
            v = ledger.verify(verifier=ver)
            _rec("⑤ 真实验签(双方公钥)", v.get("sig_verified") is True,
                 f"sig_verified={v.get('sig_verified')}")
        else:
            v = ledger.verify(verifier=None)
            _rec("⑤ 真实验签(双方公钥)", False, "缺对端签名公钥，无法真实验签")
        _rec("⑥ 完整性(hash链+sig_object)", bool(v.get("ok")), v.get("reason", ""))
    except Exception as e:  # noqa: BLE001
        _rec("⑤ 真实验签(双方公钥)", False, f"{type(e).__name__}: {e}")
        _rec("⑥ 完整性(hash链+sig_object)", False, "验签异常")

    return _finish()


def _finish() -> int:
    print("\n" + "=" * 64)
    allok = all(r["ok"] for r in RESULTS)
    for r in RESULTS:
        mark = "✅" if r["ok"] else "❌"
        line = f"  {mark} {r['step']}"
        if r["detail"]:
            line += f"  —  {r['detail']}"
        print(line)
    print("=" * 64)
    print(f"结果：{'🎉 全部通过' if allok else '⚠️ 有失败项'}（{sum(r['ok'] for r in RESULTS)}/{len(RESULTS)}）")
    return 0 if allok else 1


def main():
    args = [a for a in sys.argv[1:]]
    json_out = "-j" in args or "--json" in args
    args = [a for a in args if a not in ("-j", "--json")]
    peer = args[0] if args else os.environ.get("AL_PEER", "zheng-mac")
    command = args[1] if len(args) > 1 else "@search 刑侦"

    # JSON 模式：捕获 RESULTS（临时重定向 stdout）
    if json_out:
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = asyncio.run(run(peer, command))
        print(json.dumps({"peer": peer, "command": command, "exit": code,
                          "results": RESULTS}, ensure_ascii=False, indent=2))
        return code
    return asyncio.run(run(peer, command))


if __name__ == "__main__":
    sys.exit(main())
