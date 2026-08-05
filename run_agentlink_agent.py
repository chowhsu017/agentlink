#!/usr/bin/env python3
"""
AgentLink Swift Proxy Agent — 供 StrongAI App HTTP 控制
Swift 不跑自己的 Server，通过 HTTP 操控此代理，代理负责真协议交互。
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time, json, asyncio
import uvicorn
from fastapi import FastAPI, Request
from agentlink_p1 import AgentLinkState, create_agent_app, rpc_result, rpc_error, AgentStatus, _reset_session

PORT = 18766
NAME = "StrongAI"
DID = f"did:wba:localhost:{PORT}"

state = AgentLinkState(name=NAME, port=PORT, did=DID)
app = create_agent_app(state)

# 断线钩子：通知对方挂断（防止卡会话）
import httpx
async def _on_hangup(reason: str, sid: str, purl: str, pname: str):
    if purl and sid:
        try:
            async with httpx.AsyncClient(timeout=3) as c:
                await c.post(f"{purl}/agentlink/hangup", json={
                    "jsonrpc": "2.0",
                    "method": "agentlink.hangup",
                    "params": {
                        "meta": {"profile": "agentlink.session.v1", "session_id": sid},
                        "body": {"session_id": sid, "reason": reason}
                    }
                })
        except Exception:
            pass
state.on_hangup = _on_hangup



# ─── 消息缓冲（Swift 可轮询拉取回复） ───
_swift_messages: list = []

@app.get("/swift/messages")
async def swift_messages():
    """Swift 轮询拉取收到的消息"""
    import copy
    msgs = copy.copy(_swift_messages)
    _swift_messages.clear()
    return {"messages": msgs}


# ─── Swift 专用简化端点 ──────────────────

@app.post("/swift/call")
async def swift_call(req: Request):
    """一键呼叫：发起 + 注册 + 接受 + 连 WS + 启动心跳"""
    data = await req.json()
    body = data.get("body", data)
    target_url = body.get("target_url", "")
    target_name = body.get("target_name", "Unknown")
    session_id = body.get("session_id", __import__("uuid").uuid4().hex[:12])

    if not target_url:
        return rpc_error(-1, "target_url required")

    async with __import__("httpx").AsyncClient() as c:
        # 1. 呼叫对方
        call_payload = {
            "jsonrpc": "2.0", "method": "agentlink.call",
            "params": {
                "meta": {"profile": "agentlink.session.v1", "sender_did": DID,
                         "target_did": target_url.replace("http://", "did:wba:")},
                "body": {
                    "session_id": session_id, "caller_name": NAME,
                    "caller_url": f"http://localhost:{PORT}",
                    "caller_ws": f"ws://localhost:{PORT}/agentlink/ws/{session_id}",
                    "capabilities": {"stream_types": ["text", "json"]},
                }
            }
        }
        resp = await c.post(f"{target_url}/agentlink/call", json=call_payload, timeout=5)
        result = resp.json().get("result", {})
        if result.get("type") == "busy":
            state.tlog("call", f"{target_name} 占线", session_id)
            return rpc_result({"status": "busy", "peer": result.get("in_session_with")})
        if result.get("type") != "ring":
            return rpc_error(-1, f"call failed: {result}")

        # 2. 注册本地 session
        state.session_id = session_id
        state.peer_name = target_name
        state.peer_did = target_url.replace("http://", "did:wba:")
        state.peer_url = target_url
        state.start_time = time.time()
        state.status = AgentStatus.RINGING
        state.frames_sent = 0
        state.frames_received = 0
        state.tlog("register", f"外出会话 → {target_name}", session_id)

        # 3. 本地 + 远端接受
        accept_payload = {
            "jsonrpc": "2.0", "method": "agentlink.accept",
            "params": {"meta": {"profile": "agentlink.session.v1"},
                       "body": {"session_id": session_id}}
        }
        await c.post(f"http://localhost:{PORT}/agentlink/accept", json=accept_payload, timeout=5)
        await c.post(f"{target_url}/agentlink/accept", json=accept_payload, timeout=5)

        state.status = AgentStatus.IN_SESSION
        state.tlog("accept", f"与 {target_name} 接通", session_id)
        print(f"\n✅ {NAME}: 与 {target_name} 通联成功 (session={session_id[:8]}...)")

        # 4. 连接对方 WS（持久通道）
        peer_ws = f"ws://{target_url.replace('http://', '')}/agentlink/ws/{session_id}"
        try:
            import websockets
            ws = await websockets.connect(peer_ws)
            # 直接挂到 state.ws_conn 上
            from agentlink_p1 import WSConnection
            state.ws_conn = WSConnection()
            state.ws_conn.set_client(ws)
            state.tlog("ws_open", f"WS 持久通道 → {target_name}", session_id)
            print(f"  🔗 {NAME}: WS 持久通道已建立 → {target_name}")

            # 启动心跳
            from agentlink_p1 import _heartbeat_loop
            if state._hb_task:
                state._hb_task.cancel()
            state._hb_task = __import__("asyncio").create_task(_heartbeat_loop(state))

            # 启动 WS 接收循环（处理对方回的心跳等）
            async def _ws_recv_loop():
                while state.status == AgentStatus.IN_SESSION:
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=30)
                        try:
                            msg = json.loads(raw)
                            method = msg.get("method", "")
                            if method == "agentlink.heartbeat":
                                state._hb_missed = 0
                                state.tlog("hb", "收到对方心跳", state.session_id)
                            elif method == "agentlink.data":
                                body = msg.get("body", {})
                                payload = body.get("payload", "")
                                seq = body.get("seq", 0)
                                state.frames_received += 1
                                state.tlog("data_rx", f"收到: {payload[:60]}", state.session_id)
                                print(f"  📥 {NAME} 收到: {payload[:60]}")
                                # 缓冲到 Swift 可查询
                                _swift_messages.append({
                                    "seq": seq,
                                    "from": state.peer_name,
                                    "text": payload,
                                    "time": __import__("time").strftime("%H:%M:%S"),
                                })
                        except json.JSONDecodeError:
                            pass
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        if state.status == AgentStatus.IN_SESSION:
                            print(f"  ⚠️ {NAME}: WS 接收异常: {e}")
                        break
            __import__("asyncio").create_task(_ws_recv_loop())
        except Exception as e:
            print(f"  ⚠️ {NAME}: WS 连接失败，将使用 fallback 模式: {e}")

    return rpc_result({
        "status": "connected",
        "session_id": session_id,
        "peer_name": target_name,
        "peer_ws": f"ws://{target_url.replace('http://', '')}/agentlink/ws/{session_id}",
    })


@app.post("/swift/send")
async def swift_send(req: Request):
    """Swift 发消息（优先持久 WS，fallback 直连对方）"""
    data = await req.json()
    body = data.get("body", data)
    text = body.get("text", "")

    if not state.session_id or state.status != AgentStatus.IN_SESSION:
        return rpc_error(-1, "not in session")
    if not text:
        return rpc_error(-1, "text required")

    seq = state.next_seq()
    msg = {
        "method": "agentlink.data",
        "meta": {"profile": "agentlink.session.v1", "session_id": state.session_id},
        "body": {"seq": seq, "type": "text", "payload": text},
    }

    # 优先持久 WS
    conn = state.ws_conn
    if conn and conn.connected:
        try:
            await conn.send_json(msg)
            state.frames_sent += 1
            state.tlog("data_tx", f"[{seq}] {text[:60]}", state.session_id)
            print(f"  📤 {NAME} [{seq}]: \"{text[:40]}...\"")
            return rpc_result({"status": "sent", "seq": seq})
        except Exception as e:
            print(f"  ⚠️ 持久 WS 发送失败: {e}，回退直连")

    # fallback：直连对方 WS
    peer_url = state.peer_did.replace("did:wba:", "http://")
    try:
        import websockets
        async with websockets.connect(
            f"ws://{peer_url}/agentlink/ws/{state.session_id}"
        ) as ws:
            await ws.send(json.dumps(msg))
            state.frames_sent += 1
            state.tlog("data_tx", f"[{seq}] {text[:60]} (direct)", state.session_id)
            print(f"  📤 {NAME} [{seq}] (direct): \"{text[:40]}...\"")
            return rpc_result({"status": "sent", "seq": seq})
    except Exception as e:
        return rpc_error(-1, f"send failed: {e}")


@app.post("/swift/hangup")
async def swift_hangup(req: Request):
    """挂断"""
    data = await req.json()
    reason = (data.get("body", data)).get("reason", "user_hangup")
    state.tlog("hangup", reason, state.session_id)
    _reset_session(state, reason)
    return rpc_result({"status": "hungup"})


# ─── HomeView 场景卡片用 ──────────────────
@app.get("/agentlink/peer/status")
async def peer_status():
    """对方在线状态"""
    if state.peer_did:
        peer_url = state.peer_did.replace("did:wba:", "http://")
        try:
            import httpx
            async with httpx.AsyncClient() as c:
                r = await c.get(f"{peer_url}/status", timeout=3)
                return r.json()
        except:
            pass
    return state.to_dict()


if __name__ == "__main__":
    print(f"\n🦾 StrongAI AgentLink 代理启动 @ :{PORT}")
    print(f"   Swift 通过 HTTP 控制此代理，代理与其他 Agent 交互")
    print(f"   HTTP: http://localhost:{PORT}")
    print(f"   WS:   ws://localhost:{PORT}/agentlink/ws\n")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="error")
