#!/usr/bin/env python3
"""
AgentLink 交互式发送端 — 供 zheng-mac(或任何对端) 加密发请求到 tiger-mac
运行后在终端直接输入命令回车即加密发送：
  @search <关键词>   → 触发 tiger-mac 本地素材库搜索
  (其他)             → 普通加密消息
用法: .venv/bin/python3 send_interactive.py
依赖: 需 zheng-mac 自己的 keypair 和 DID
"""
import sys, os, asyncio, json, uuid

SRC = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC)

# ── 可配置区（把硬编码的机器信息改为环境变量，避免推公开仓库泄漏拓扑）──
# 本机（发送端）身份
MY_KEY = os.environ.get("AGENTLINK_MY_KEY", os.path.expanduser("~/.agentlink/key.json"))
MY_NAME = os.environ.get("AGENTLINK_MY_NAME", "agent")
MY_PORT = int(os.environ.get("AGENTLINK_MY_PORT", "18790"))
MY_IP = os.environ.get("AGENTLINK_MY_IP", "127.0.0.1")

# 对端（执行端）地址 —— 通过命令行或环境变量指定，不写死
TIGER_HTTP = os.environ.get("AGENTLINK_PEER_HTTP", "http://127.0.0.1:18799")
TIGER_WS = os.environ.get("AGENTLINK_PEER_WS", "ws://127.0.0.1:18799/agentlink/ws")
TIGER_DID = os.environ.get("AGENTLINK_PEER_DID", "did:agentlink:peer:")


def make_data_frame(state, seq, payload):
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


async def send_once(text, secure, state):
    """向 tiger-mac 建会话并发一条加密消息，等待并打印回传"""
    import httpx, websockets
    from agentlink import _unb64, compute_shared_secret, derive_session_key, SessionCipher

    state.session_id = str(uuid.uuid4())

    # 1) CALL tiger-mac 拿 responder 公钥 + salt，建 cipher
    r = httpx.post(f"{TIGER_HTTP}/agentlink/call", json={
        "jsonrpc":"2.0","method":"agentlink.call","params":{
            "meta":{"profile":"agentlink.session.v1","sender_did":state.did,"target_did":TIGER_DID},
            "body":{"session_id":state.session_id,"caller_name":state.name,
                    "caller_url":f"http://{MY_IP}:{MY_PORT}",
                    "caller_ws":f"ws://{MY_IP}:{MY_PORT}/agentlink/ws",
                    "enc_public_b64": secure.get_auth_payload()["enc_public_b64"],
                    "sign_public_b64": secure.get_auth_payload()["sign_public_b64"]}}}, timeout=6)
    res = r.json().get("result", {})
    if res.get("type") != "ring":
        print(f"❌ CALL 失败: {res}"); return
    peer_did = res.get("peer_did") or TIGER_DID
    shared = compute_shared_secret(secure.kp.enc_private, _unb64(res["enc_public_b64"]))
    key, salt = derive_session_key(shared, _unb64(res["salt"]))
    secure.cipher = SessionCipher(key, salt, state.did, peer_did)
    secure.e2ee_enabled = True

    # 2) 连 WS 发加密帧
    zs_url = f"{TIGER_WS}/{state.session_id}"
    async with websockets.connect(zs_url) as ws:
        await asyncio.sleep(0.5)
        enc = secure.encrypt_payload(text)
        await ws.send(json.dumps(make_data_frame(state, 1, enc)))
        print(f"📤 已发送: \"{text[:50]}\" (加密)")
        # 等回传
        try:
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=10)
                data = json.loads(raw)
                method = data.get("method", "")
                body = data.get("body", {})
                if method == "agentlink.data":
                    payload = body.get("payload", "")
                    # 可能是加密回传，尝试解密
                    if isinstance(payload, str) and payload.startswith("🔒") and secure.cipher:
                        try:
                            from agentlink import _unb64
                            dec = secure.cipher.decrypt(_unb64(payload[1:]))
                            print(f"\n📨 tiger-mac 回传(解密):\n{dec.decode('utf-8')}")
                        except Exception as e:
                            print(f"\n📨 tiger-mac 回传(密文): {payload[:80]} ({e})")
                    else:
                        print(f"\n📨 tiger-mac 回传(明文): {payload[:500]}")
                    break
                # 跳过 ACK
        except asyncio.TimeoutError:
            print("⏳ 10s 内没等到回传")


async def main():
    from agentlink.secure_session import create_secure_agent
    state, secure = create_secure_agent(MY_NAME, MY_PORT, keypair_path=MY_KEY)
    state.secure = secure
    state.did = secure.kp.did
    state.http_url = f"http://{MY_IP}:{MY_PORT}"

    print("=" * 50)
    print(f"AgentLink 发送端（→ tiger-mac 执行能力）")
    print(f"我的 DID: {state.did}")
    print(f"命令: @search <关键词>  = 远程搜索 tiger-mac 素材库")
    print(f"      quit             = 退出")
    print("=" * 50)
    while True:
        try:
            text = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n👋 退出"); break
        if not text:
            continue
        if text.lower() in ("quit", "exit", "q"):
            print("👋 退出"); break
        await send_once(text, secure, state)


if __name__ == "__main__":
    asyncio.run(main())
