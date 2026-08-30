#!/usr/bin/env python3
"""tiger-mac → zheng-mac 加密通知发送（跨机感知，非 @search）
用于把 tiger-mac 侧的结果/进度加密推给对端 zheng-mac，对端 agent 解密后可感知。
用法: .venv/bin/python3 notify_zheng.py "<消息>"
"""
import sys, os, asyncio, json, uuid
SRC = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC)
import httpx, websockets
from agentlink import load_keypair, _unb64, compute_shared_secret, derive_session_key, SessionCipher
from agentlink.secure_session import create_secure_agent

KEY = os.path.expanduser("~/.openclaw/workspace/agentlink_tiger-mac.key.json")
ZH_HTTP = os.environ.get("AL_ZH_HTTP", "http://192.168.1.7:18790")
ZH_WS   = os.environ.get("AL_ZH_WS", "ws://192.168.1.7:18790/agentlink/ws")
ZH_DID  = os.environ.get("AL_ZH_DID", "did:agentlink:zheng-mac:Z1Rd+LemnMSJZT8/")
NAME, MY_IP = "tiger-mac", "192.168.1.115"


def frame(state, seq, payload):
    return {"method": "agentlink.data",
            "meta": {"profile": "agentlink.session.v1", "sender_did": state.did,
                     "sender_name": state.name, "session_id": state.session_id},
            "body": {"seq": seq, "type": "text", "payload": payload}}


async def notify(text):
    sid = f"nt-{uuid.uuid4().hex[:8]}"
    state, secure = create_secure_agent(NAME, 18799, keypair_path=KEY)
    state.secure = secure; state.session_id = sid; state.did = secure.kp.did
    state.http_url = f"http://{MY_IP}:18799"

    r = httpx.post(f"{ZH_HTTP}/agentlink/call", json={
        "jsonrpc": "2.0", "method": "agentlink.call", "params": {
            "meta": {"profile": "agentlink.session.v1", "sender_did": state.did, "target_did": ZH_DID},
            "body": {"session_id": sid, "caller_name": NAME, "caller_url": state.http_url,
                     "caller_ws": f"ws://{MY_IP}:18799/agentlink/ws",
                     "enc_public_b64": secure.get_auth_payload()["enc_public_b64"],
                     "sign_public_b64": secure.get_auth_payload()["sign_public_b64"]}}}, timeout=6)
    res = r.json().get("result", {})
    if res.get("type") != "ring":
        print(f"❌ CALL 失败: {str(res)[:120]}"); return False
    peer = res.get("peer_did") or ZH_DID
    shared = compute_shared_secret(secure.kp.enc_private, _unb64(res["enc_public_b64"]))
    key, salt = derive_session_key(shared, _unb64(res["salt"]))
    secure.cipher = SessionCipher(key, salt, state.did, peer)
    secure.e2ee_enabled = True
    state.peer_did = peer   # 覆盖占位符/空 → 触发 v0.1.4 encrypt 断言通过的合法路径

    async with websockets.connect(f"{ZH_WS}/{sid}") as ws:
        await asyncio.sleep(0.8)
        enc = secure.encrypt_payload(text)
        await ws.send(json.dumps(frame(state, 1, enc)))
        print(f"📤 已加密发送 → zheng-mac: \"{text[:60]}\"")
        # 等对端 ACK/回执
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=6)
            print(f"📨 对端回执: {str(raw)[:120]}")
        except asyncio.TimeoutError:
            print("ℹ️ 6s 无回执（对端可能仅接收不留痕，加密已送达）")
    return True


if __name__ == "__main__":
    msg = sys.argv[1] if len(sys.argv) > 1 else "tiger-mac 问候：跨机加密链路已打通"
    sys.exit(0 if asyncio.run(notify(msg)) else 1)
