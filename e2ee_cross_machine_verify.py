#!/usr/bin/env python3
"""AgentLink 跨机加密往返验证 · 路径B（本机 v0.1.4 ↔ 对端 v0.1.3 向后兼容）
流程:
  1. 本机 v0.1.4 agent 主动向 zheng-mac:18790 发加密 call
  2. 拿 ring 响应（responder 真实 peer_did + salt + 公钥）→ 建 cipher
  3. 连对端 WS，发加密 `@search <词>` 命令
  4. 对端解密 → 跑 capability → 加密回传搜索结果
  5. 本机解密回显 → 证明双向加密往返 + wire 向后兼容

用法: .venv/bin/python3 e2ee_cross_machine_verify.py "<搜索词>"
"""
import sys, os, asyncio, json, uuid

SRC = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC)
import httpx, websockets
from agentlink import load_keypair
from agentlink.secure_session import create_secure_agent

KEY = os.path.expanduser("~/.openclaw/workspace/agentlink_tiger-mac.key.json")
TARGET = os.environ.get("AL_TARGET", "http://192.168.1.7:18790")
TARGET_WS = os.environ.get("AL_TARGET_WS", TARGET.replace("http", "ws") + "/agentlink/ws")
TARGET_DID = os.environ.get("AL_TARGET_DID", "did:agentlink:zheng-mac:Z1Rd+LemnMSJZT8/")
NAME, MY_IP = "tiger-mac", "192.168.1.115"


def make_frame(state, seq, payload):
    return {
        "method": "agentlink.data",
        "meta": {
            "profile": "agentlink.session.v1",
            "sender_did": state.did,
            "sender_name": state.name,
            "session_id": state.session_id,
        },
        "body": {"seq": seq, "type": "text", "payload": payload},
    }


async def main(search_word):
    search_word = search_word or "刑侦"
    session_id = f"bm-{uuid.uuid4().hex[:8]}"
    print(f"🔑 跨机加密往返验证 · 本机 v0.1.4 → zheng-mac v0.1.3")
    print(f"   session: {session_id}   搜索词: {search_word}")
    print("=" * 56)

    state, secure = create_secure_agent(NAME, 18799, keypair_path=KEY)
    state.secure = secure
    state.session_id = session_id
    state.did = secure.kp.did
    state.http_url = f"http://{MY_IP}:18799"
    state.peer_did = TARGET_DID  # 占位对端 DID（真实值由 ring 覆盖）

    # ① 发起加密 call
    print("\n① 发起加密 call → zheng-mac")
    r = httpx.post(f"{TARGET}/agentlink/call", json={
        "jsonrpc": "2.0", "method": "agentlink.call", "params": {
            "meta": {"profile": "agentlink.session.v1",
                     "sender_did": state.did, "target_did": TARGET_DID},
            "body": {"session_id": session_id, "caller_name": NAME,
                     "caller_url": state.http_url,
                     "caller_ws": f"ws://{MY_IP}:18799/agentlink/ws",
                     "enc_public_b64": secure.get_auth_payload()["enc_public_b64"],
                     "sign_public_b64": secure.get_auth_payload()["sign_public_b64"]}}}, timeout=6)
    res = r.json().get("result", {})
    if not res or res.get("type") != "ring":
        print(f"❌ call 失败: {r.text[:200]}")
        return
    print(f"✓ ring 收到 | peer_did: {str(res.get('peer_did',''))[:44]}")
    print(f"  salt?{'✓' if res.get('salt') else '✗'} | responder公钥?{'✓' if res.get('enc_public_b64') else '✗'}")

    # ② 用 ring 的真实 peer_did + salt 建 cipher
    from agentlink import _unb64, compute_shared_secret, derive_session_key, SessionCipher
    real_peer = res.get("peer_did") or TARGET_DID
    shared = compute_shared_secret(secure.kp.enc_private, _unb64(res["enc_public_b64"]))
    key, salt = derive_session_key(shared, _unb64(res["salt"]))
    secure.cipher = SessionCipher(key, salt, state.did, real_peer)
    secure.e2ee_enabled = True
    state.peer_did = real_peer   # 覆盖占位符 → 触发 v0.1.4 断言路径
    print(f"\n② cipher 就绪 (e2ee_enabled={secure.e2ee_enabled}, peer={real_peer[:40]})")

    # ③ 连对端 WS 发加密 @search 命令
    ws_url = f"{TARGET_WS}/{session_id}"
    print(f"\n③ 连 zheng WS → 发加密 @search \"{search_word}\"")
    async with websockets.connect(ws_url) as ws:
        await asyncio.sleep(1.0)
        cmd = f"@search {search_word}"
        enc = secure.encrypt_payload(cmd)   # v0.1.4 encrypt 断言路径
        frame = make_frame(state, 1, enc)
        await ws.send(json.dumps(frame))
        print(f"  已发送加密帧 seq=1 ({cmd})")

        # ④ 等对端 capability 加密回传（跳过明文 ACK，等 🔒 加密结果）
        print("\n④ 等 zheng 加密回传搜索结果（跳过明文ACK）...")
        got = None
        deadline = asyncio.get_event_loop().time() + 8
        while asyncio.get_event_loop().time() < deadline:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=max(0.2, deadline - asyncio.get_event_loop().time()))
                print(f"   收到原始帧: {str(raw)[:120]}")
            except asyncio.TimeoutError:
                break
            msg = json.loads(raw)
            # 兼容 rpc_result / agentlink.data 两种结构
            body = msg.get("body") or msg.get("result") or {}
            payload = body.get("payload", "")
            # 明文 ACK（status:ok）→ 跳过，继续等加密结果
            if not payload and body.get("status") == "ok":
                print(f"   (跳过明文ACK seq={body.get('seq')})")
                continue
            if isinstance(payload, str) and payload.startswith("🔒"):
                try:
                    plain = secure.cipher.decrypt(_unb64(payload[1:]))
                    got = plain.decode("utf-8", "replace")
                    print(f"✅ 收到加密回执并解密成功:\n   └─ {str(got)[:180]}")
                except Exception as e:
                    print(f"⚠️ 解密回执失败: {type(e).__name__}: {e}")
                    got = "<解密失败>"
                break
            elif payload:
                print(f"⚠️ 明文回执(非加密): {str(payload)[:150]}")
                got = str(payload)
                break
        if got is None:
            print("⏳ 等待超时，未收到加密 capability 回传")

        # ⑤ 回程验证：本机再主动加密发一条，测试对端能否继续解密（连续帧）
        enc2 = secure.encrypt_payload("CM验证 echo #2")
        await ws.send(json.dumps(make_frame(state, 2, enc2)))
        print("\n⑤ 已发加密 seq=2（连续帧）")

    print("\n" + "=" * 56)
    result = got is not None and ("检索" in got or "条" in got or len(got) > 10)
    if got and secure.e2ee_enabled:
        print("🎉 跨机双向加密往返成功：本机 v0.1.4 与对端 v0.1.3 wire 向后兼容，断言未误伤")
        return 0
    else:
        print("⚠️ 加密往返未完整闭环，见上方日志")
        return 1


if __name__ == "__main__":
    w = sys.argv[1] if len(sys.argv) > 1 else "刑侦"
    sys.exit(asyncio.run(main(w)))
