"""
AgentLink P1 — WebSocket 双向流 + 心跳保活 + 断线重连
P2 — 频道模式 + Presence
========================================
核心实现，替换 agentlink_p0.py
"""
from __future__ import annotations
import asyncio, json, uuid, time, struct
from dataclasses import dataclass, field
from typing import Optional, Callable
from enum import Enum
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, HTMLResponse
import httpx


# ─── 常量 ─────────────────────────────────────

HEARTBEAT_INTERVAL = 15     # 秒
HEARTBEAT_TIMEOUT = 3       # 连续缺 N 次判定离线
RECONNECT_TIMEOUT = 30      # 断线重连窗口
DEFAULT_WS_PORT = 0         # 0 = 与 HTTP 同端口


# ─── 错误码 ─────────────────────────────────────

class AgentLinkError(Enum):
    OK = 0
    SESSION_MISMATCH = -1
    PEER_BUSY = -2
    TIMEOUT = -3
    CONNECTION_LOST = -4
    NOT_FOUND = -5
    ALREADY_IN_SESSION = -6


# ─── Agent 状态 ─────────────────────────────────

class AgentStatus(Enum):
    IDLE = "idle"
    RINGING = "ringing"
    IN_SESSION = "in_session"
    AWAY = "away"
    INVISIBLE = "invisible"


# ─── Timeline 事件日志 ──────────────────────────

@dataclass
class TimelineEvent:
    """通联事件日志——用于可视化时间线和书里截图"""
    agent: str
    event_type: str  # call | ring | accept | reject | ws_open | ws_close | data_tx | data_rx | hb | hangup
    detail: str = ""
    ts: float = field(default_factory=time.time)
    session_id: str = ""

    @property
    def ts_str(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.ts)) + f".{int((self.ts % 1) * 1000):03d}"

    def to_dict(self):
        return {
            "agent": self.agent,
            "event": self.event_type,
            "detail": self.detail,
            "ts": round(self.ts, 3),
            "ts_str": self.ts_str,
            "session_id": self.session_id,
        }


@dataclass
class SessionRecord:
    session_id: str
    peer_did: str
    peer_name: str
    start_time: float
    end_time: float = 0.0
    frames_sent: int = 0
    frames_received: int = 0
    reason: str = ""

    @property
    def duration_sec(self) -> float:
        end = self.end_time if self.end_time else time.time()
        return round(end - self.start_time, 1)

    def to_dict(self):
        return {
            "session_id": self.session_id,
            "peer": self.peer_name,
            "duration_sec": self.duration_sec,
            "frames_sent": self.frames_sent,
            "frames_received": self.frames_received,
            "reason": self.reason,
        }


class AgentLinkState:
    """单 agent 完整状态"""

    def __init__(self, name: str, port: int, did: str):
        self.name = name
        self.port = port
        self.did = did
        self.http_url = f"http://localhost:{port}"
        self.ws_url = f"ws://localhost:{port}/agentlink/ws"

        # Timeline 事件缓冲区
        self.timeline: list[TimelineEvent] = []
        self._timeline_lock = asyncio.Lock()
        self._timeline_queue: asyncio.Queue = asyncio.Queue()  # SSE 推送用

        # 会话状态
        self.status = AgentStatus.IDLE
        self.session_id: Optional[str] = None
        self.peer_did: Optional[str] = None
        self.peer_url: Optional[str] = None
        self.peer_name: Optional[str] = None
        self.peer_ws: Optional[str] = None
        self.start_time: float = 0.0
        self.frames_sent = 0
        self.frames_received = 0
        self.seq = 0

        # WebSocket 连接
        self.ws_conn: Optional["WebSocketConnection"] = None
        self._ws_server: Optional[WebSocket] = None  # 服务端 WS
        self._ws_client: Optional[any] = None         # 客户端 WS

        # 心跳
        self._hb_task: Optional[asyncio.Task] = None
        self._hb_missed = 0

        # 历史
        self.history: list[SessionRecord] = []
        self._history_lock = asyncio.Lock()

        # 回调注册
        self.on_data: Optional[Callable] = None   # data(payload, seq, type)
        self.on_ring: Optional[Callable] = None   # ring(caller, session_id)
        self.on_accept: Optional[Callable] = None # accept()
        self.on_hangup: Optional[Callable] = None # hangup(reason)

        # P2: 频道
        self.channels: dict[str, set] = {}  # channel_id → {subscriber WS}

        # P2: Presence
        self._presence_clients: dict[str, asyncio.Queue] = {}
        self.presence_status: dict[str, dict] = {}
        self._publish_own_presence()

    def tlog(self, event_type: str, detail: str = "", session_id: str = ""):
        """记录 timeline 事件"""
        evt = TimelineEvent(
            agent=self.name,
            event_type=event_type,
            detail=detail,
            session_id=session_id or self.session_id or "",
        )
        # 同步追加到缓冲区
        self.timeline.append(evt)
        # 异步推送到 SSE
        asyncio.ensure_future(self._push_timeline(evt))

    async def _push_timeline(self, evt: TimelineEvent):
        await self._timeline_queue.put(evt.to_dict())

    def _publish_own_presence(self):
        self.presence_status[self.did] = {
            "name": self.name,
            "status": self.status.value,
            "url": self.http_url,
            "ws": self.ws_url,
            "since": time.strftime("%H:%M:%S"),
        }

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    async def add_history(self, rec: SessionRecord):
        async with self._history_lock:
            self.history.append(rec)

    def to_dict(self):
        return {
            "name": self.name,
            "did": self.did,
            "url": self.http_url,
            "status": self.status.value,
            "session_id": self.session_id,
            "peer": self.peer_name,
            "frames": {"sent": self.frames_sent, "received": self.frames_received},
            "duration_sec": round(time.time() - self.start_time, 1) if self.session_id else 0,
        }

    # ─── 频道 API ───

    def subscribe_channel(self, channel_id: str, ws_sender):
        if channel_id not in self.channels:
            self.channels[channel_id] = set()
        self.channels[channel_id].add(ws_sender)
        return True

    def unsubscribe_channel(self, channel_id: str, ws_sender):
        if channel_id in self.channels:
            self.channels[channel_id].discard(ws_sender)

    async def broadcast_channel(self, channel_id: str, payload: dict):
        if channel_id not in self.channels:
            return 0
        sent = 0
        dead = set()
        for ws in self.channels[channel_id]:
            try:
                await ws.send_json(payload)
                sent += 1
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.channels[channel_id].discard(ws)
        return sent

    # ─── Presence API ───

    async def subscribe_presence(self, subscriber: str, queue: asyncio.Queue):
        self._presence_clients[subscriber] = queue

    async def unsubscribe_presence(self, subscriber: str):
        self._presence_clients.pop(subscriber, None)

    async def notify_presence_change(self):
        """当自身状态变化时通知所有 presence 订阅者"""
        self._publish_own_presence()
        update = self.presence_status[self.did]
        dead = []
        for subscriber, queue in self._presence_clients.items():
            try:
                await queue.put(update)
            except Exception:
                dead.append(subscriber)
        for s in dead:
            self._presence_clients.pop(s, None)


# ─── WebSocket 连接管理 ────────────────────

class WSConnection:
    """封装 WS 发送（让 handler 不需要区分 server/client）"""

    def __init__(self):
        self._server: Optional[WebSocket] = None
        self._client: Optional[any] = None
        self._connected = False

    def set_server(self, ws: WebSocket):
        self._server = ws
        self._connected = True

    def set_client(self, ws):
        self._client = ws
        self._connected = True

    @property
    def connected(self) -> bool:
        return self._connected

    async def send_json(self, data: dict):
        err = None
        if self._server:
            try:
                await self._server.send_json(data)
                return
            except Exception as e:
                err = e
                self._server = None
        if self._client:
            try:
                import json
                await self._client.send(json.dumps(data))
                return
            except Exception as e:
                err = e
                self._client = None
        self._connected = False
        if err:
            raise err

    async def close(self):
        self._connected = False
        if self._server:
            try:
                await self._server.close()
            except Exception:
                pass
            self._server = None
        if self._client:
            try:
                await self._client.close()
            except Exception:
                pass
            self._client = None

    async def receive_json(self):
        if self._server:
            return await self._server.receive_json()
        raise ConnectionError("No active WebSocket")


# ─── 辅助函数 ────────────────────────────────

def _meta(data: dict) -> dict:
    return data.get("params", {}).get("meta", {})

def _body(data: dict) -> dict:
    return data.get("params", {}).get("body", {})

def rpc_result(payload: dict) -> dict:
    return {"jsonrpc": "2.0", "result": payload}

def rpc_error(code: int, msg: str) -> dict:
    return {"jsonrpc": "2.0", "error": {"code": code, "message": msg}}

def ws_message(method: str, state: AgentLinkState, body: dict) -> dict:
    return {
        "method": method,
        "meta": {
            "profile": "agentlink.session.v1",
            "sender_did": state.did,
            "sender_name": state.name,
            "session_id": state.session_id or "",
        },
        "body": body,
    }


# ═══════════════════════════════════════════════
# P1: FastAPI App 工厂
# ═══════════════════════════════════════════════

def create_agent_app(state: AgentLinkState):
    """创建含 HTTP 信令 + WebSocket 流的 FastAPI app"""

    app = FastAPI(title=f"AgentLink - {state.name}")

    # ─── HTTP 信令（复用 ANP JSON-RPC 风格）───

    @app.post("/agentlink/call")
    async def handle_call(req: Request):
        data = await req.json()
        body = _body(data)
        session_id = body.get("session_id", str(uuid.uuid4()))
        caller_name = body.get("caller_name", "Unknown")
        caller_did = _meta(data).get("sender_did", "unknown")
        caller_ws = body.get("caller_ws", "")
        caller_http = body.get("caller_url", "")

        if state.status == AgentStatus.IN_SESSION:
            return rpc_result({
                "type": "busy",
                "session_id": session_id,
                "in_session_with": state.peer_name,
            })

        # 振铃
        state.status = AgentStatus.RINGING
        state.session_id = session_id
        state.peer_did = caller_did
        state.peer_name = caller_name
        state.peer_ws = caller_ws
        state.start_time = time.time()
        state.frames_sent = 0
        state.frames_received = 0
        state.seq = 0

        state.tlog("call", f"来自 {caller_name} 的呼叫", session_id)
        print(f"\n📞 {state.name}: 收到来自 {caller_name} 的呼叫 (session={session_id[:8]}...)")

        if state.on_ring:
            state.on_ring(caller_name, session_id)

        return rpc_result({
            "type": "ring",
            "session_id": session_id,
            "ring_at": time.strftime("%H:%M:%S"),
            "timeout_sec": 30,
            "ws_url": f"{state.ws_url}/{session_id}",
        })

    @app.post("/agentlink/accept")
    async def handle_accept(req: Request):
        data = await req.json()
        body = _body(data)
        sid = body.get("session_id", "")

        if state.session_id != sid:
            return rpc_error(-1, f"session mismatch: {state.session_id} != {sid}")

        state.status = AgentStatus.IN_SESSION
        state.tlog("accept", f"与 {state.peer_name} 接通", state.session_id)
        print(f"\n📞 {state.name}: 呼叫已接通！与 {state.peer_name} 会话中")

        # 启动心跳
        if state._hb_task:
            state._hb_task.cancel()
        state._hb_task = asyncio.create_task(_heartbeat_loop(state))

        if state.on_accept:
            state.on_accept()

        return rpc_result({
            "status": "accepted",
            "ws_url": f"{state.ws_url}/{sid}",
        })

    @app.post("/agentlink/reject")
    async def handle_reject(req: Request):
        data = await req.json()
        body = _body(data)
        sid = data.get("body", {}).get("session_id", "")
        reason = body.get("reason", "rejected")

        if state.session_id == sid or sid == "":
            state.tlog("reject", reason, state.session_id)
            _reset_session(state, "rejected" if state.session_id == sid else reason)

        return rpc_result({"status": "rejected"})

    @app.post("/agentlink/register_session")
    async def handle_register_session(req: Request):
        """让本方服务器注册一个外出会话（呼叫方在收到 ring 后调用）"""
        data = await req.json()
        body = _body(data)
        sid = body.get("session_id", "")
        peer_name = body.get("peer_name", "")
        peer_url = body.get("peer_url", "")

        if not sid:
            return rpc_error(-1, "session_id required")

        state.session_id = sid
        state.peer_name = peer_name
        state.peer_did = peer_url.replace("http://", "did:wba:")
        state.peer_url = peer_url
        state.start_time = time.time()
        state.status = AgentStatus.RINGING
        state.frames_sent = 0
        state.frames_received = 0
        state.seq = 0

        state.tlog("register", f"外出会话 → {peer_name}", sid)
        print(f"\n📞 {state.name}: 注册外出会话 {sid[:8]}...  → {peer_name}")
        return rpc_result({"status": "registered", "session_id": sid})

    @app.post("/agentlink/hangup")
    async def handle_hangup(req: Request):
        data = await req.json()
        meta = _meta(data)
        body = _body(data)
        sid = meta.get("session_id", "")

        state.tlog("hangup", body.get("reason", "remote_hangup"), sid)
        if state.session_id == sid:
            _reset_session(state, body.get("reason", "remote_hangup"),
                           body.get("frames_sent", 0), body.get("frames_received", 0))
        elif state.status != AgentStatus.IDLE:
            # session_id 不匹配但还在通话中 → 强制清除
            _reset_session(state, "force_" + body.get("reason", "remote_hangup"),
                           body.get("frames_sent", 0), body.get("frames_received", 0))

        return rpc_result({"status": "hungup"})

    @app.get("/agentlink/ad.json")
    async def get_ad():
        """Agent Description — 兼容 ANP 格式"""
        return {
            "protocolType": "AgentLink",
            "protocolVersion": "0.1.0",
            "type": "Product",
            "url": f"{state.http_url}/agentlink/ad.json",
            "identifier": state.did,
            "name": state.name,
            "description": f"AgentLink Agent — {state.name}",
            "interfaces": [
                {
                    "type": "AgentLinkSessionInterface",
                    "profile": "agentlink.session.v1",
                    "binding": "jsonrpc-2.0",
                    "url": f"{state.http_url}/agentlink",
                    "ws_url": state.ws_url,
                    "methods": ["agentlink.call", "agentlink.accept", "agentlink.reject",
                                "agentlink.hangup", "agentlink.channel.subscribe",
                                "agentlink.channel.broadcast", "agentlink.presence.subscribe"],
                    "capabilities": {
                        "stream_types": ["text", "json"],
                        "max_session_sec": 3600,
                        "heartbeat_interval": HEARTBEAT_INTERVAL,
                    },
                }
            ],
        }

    # ─── 状态查询 ───

    @app.get("/status")
    async def get_status():
        return state.to_dict()

    @app.get("/history")
    async def get_history():
        async with state._history_lock:
            return [h.to_dict() for h in state.history]

    @app.get("/presence/{did}")
    async def get_presence(did: str):
        p = state.presence_status.get(did, state.presence_status.get(state.did))
        if not p:
            return rpc_error(-5, "not found")
        return rpc_result(p)

    # ─── Timeline 可视化 ───

    @app.get("/timeline")
    async def get_timeline():
        async with state._timeline_lock:
            return [e.to_dict() for e in state.timeline[-200:]]

    @app.get("/timeline/stream")
    async def timeline_stream():
        """SSE 实时推送 timeline 事件"""
        async def event_generator():
            while True:
                data = await state._timeline_queue.get()
                yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream",
                                 headers={
                                     "Cache-Control": "no-cache",
                                     "Connection": "keep-alive",
                                     "X-Accel-Buffering": "no",
                                 })

    @app.get("/timeline/dashboard")
    async def timeline_dashboard():
        """实时时间线 HTML 看板（独立文件）"""
        import os
        html_path = os.path.join(os.path.dirname(__file__), "agentlink_timeline.html")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                html = f.read()
            return HTMLResponse(html.replace("{name}", state.name).replace("{port}", str(state.port)),
                                media_type="text/html")
        return HTMLResponse("<h1>需要 agentlink_timeline.html</h1><p>请把看板HTML放在同一目录</p>",
                            status_code=404, media_type="text/html")

    @app.get("/presence")
    async def get_all_presence():
        return rpc_result(list(state.presence_status.values()))


    # ─── P1: WebSocket 端点 ───

    @app.websocket("/agentlink/ws/{session_id}")
    async def ws_handler(websocket: WebSocket, session_id: str):
        await websocket.accept()
        state.tlog("ws_open", f"WebSocket 连接建立", session_id)
        print(f"  🔗 {state.name}: WebSocket 连接建立 (session={session_id[:8]}...)")

        if state.session_id == session_id:
            if state.ws_conn is None:
                state.ws_conn = WSConnection()
            state.ws_conn.set_server(websocket)
        else:
            # 非当前session的连接，关联到 session_id
            pass

        try:
            while True:
                data = await websocket.receive_json()
                method = data.get("method", "")
                body = data.get("body", {})
                meta = data.get("meta", {})

                if method == "agentlink.data":
                    sid = meta.get("session_id", "")
                    if sid and sid != state.session_id:
                        await websocket.send_json(rpc_error(-1, "session mismatch"))
                        continue
                    state.frames_received += 1
                    seq = body.get("seq", 0)
                    payload = body.get("payload", "")
                    dtype = body.get("type", "text")
                    state.tlog("data_rx", f"[{seq}] {payload[:80]}", sid)
                    print(f"  📨 {state.name} [{seq}] 收到: \"{payload[:60]}\"")
                    await websocket.send_json(rpc_result({"status": "ok", "seq": seq}))

                    # 自动回复
                    auto_replies = {
                        "晚上好": "晚上好！收到你的消息了 😊",
                        "你好": "你好！我在线",
                        "hi": "Hi there! I'm Alice",
                        "hello": "Hello! Alice here",
                    }
                    reply_text = None
                    for kw, reply in auto_replies.items():
                        if kw in payload.lower():
                            reply_text = reply
                            break
                    if reply_text:
                        reply_seq = state.next_seq()
                        reply_frame = ws_message("agentlink.data", state, {
                            "seq": reply_seq,
                            "type": "text",
                            "payload": reply_text,
                        })
                        await websocket.send_json(reply_frame)
                        state.frames_sent += 1
                        state.tlog("data_tx", f"[auto] {reply_text[:60]}", sid)
                        print(f"  📤 {state.name} [auto] 回复: \"{reply_text[:60]}\"")
                    elif state.on_data:
                        state.on_data(payload, seq, dtype)

                elif method == "agentlink.heartbeat":
                    state._hb_missed = 0
                    state.tlog("hb", "收到心跳", meta.get("session_id", ""))
                    seq = body.get("seq", 0)
                    # 也用 agentlink.heartbeat 格式回复，让对方能识别
                    reply = ws_message("agentlink.heartbeat", state, {
                        "status": "alive",
                        "seq": seq,
                        "timestamp": time.strftime("%H:%M:%S"),
                    })
                    await websocket.send_json(reply)

                elif method == "agentlink.channel.subscribe":
                    channel_id = body.get("channel_id", "")
                    mode = body.get("mode", "readonly")
                    state.subscribe_channel(channel_id, websocket)
                    print(f"  📻 {state.name}: 订阅频道 {channel_id} (mode={mode})")
                    await websocket.send_json(rpc_result({
                        "status": "subscribed",
                        "channel_id": channel_id,
                        "mode": mode,
                    }))

                elif method == "agentlink.channel.unsubscribe":
                    channel_id = body.get("channel_id", "")
                    state.unsubscribe_channel(channel_id, websocket)
                    await websocket.send_json(rpc_result({
                        "status": "unsubscribed",
                        "channel_id": channel_id,
                    }))

                elif method == "agentlink.channel.broadcast":
                    channel_id = body.get("channel_id", "")
                    payload = body.get("payload", "")
                    ptype = body.get("type", "text")
                    broadcast_body = {
                        "sender": state.name,
                        "type": ptype,
                        "payload": payload,
                        "timestamp": time.strftime("%H:%M:%S"),
                    }
                    msg = ws_message("agentlink.channel.event", state, broadcast_body)
                    sent = await state.broadcast_channel(channel_id, msg)
                    await websocket.send_json(rpc_result({
                        "status": "broadcast",
                        "channel_id": channel_id,
                        "subscribers": sent,
                    }))

                elif method == "agentlink.presence.subscribe":
                    subscriber = body.get("subscriber_did", state.did)
                    q = asyncio.Queue()
                    await state.subscribe_presence(subscriber, q)
                    await websocket.send_json(rpc_result({
                        "status": "presence_subscribed",
                        "subscriber": subscriber,
                    }))

                    # 启动 push 任务
                    async def push_presence():
                        try:
                            while True:
                                update = await q.get()
                                await websocket.send_json(
                                    ws_message("agentlink.presence.event", state, update)
                                )
                        except Exception:
                            pass
                    asyncio.create_task(push_presence())

                else:
                    await websocket.send_json(rpc_error(-99, f"unknown method: {method}"))

        except WebSocketDisconnect:
            state.tlog("ws_close", f"WebSocket 断开", session_id)
            print(f"  ⚠️ {state.name}: WebSocket 断开 (session={session_id[:8]}...)")
        except Exception as e:
            print(f"  ⚠️ {state.name}: WebSocket 错误: {e}")
        finally:
            if state.ws_conn:
                state.ws_conn._connected = False

    return app


# ─── 心跳循环 ──────────────────────────────

async def _heartbeat_loop(state: AgentLinkState):
    """心跳保活协程"""
    while state.status == AgentStatus.IN_SESSION:
        try:
            if state.ws_conn and state.ws_conn.connected:
                msg = ws_message("agentlink.heartbeat", state, {
                    "seq": state.next_seq(),
                    "timestamp": time.strftime("%H:%M:%S"),
                })
                await state.ws_conn.send_json(msg)
                state.tlog("hb", "发送心跳", state.session_id)

            state._hb_missed += 1
            if state._hb_missed >= HEARTBEAT_TIMEOUT:
                state.tlog("hb_timeout", "心跳超时，判定掉线", state.session_id)
                print(f"  ❤️ {state.name}: 心跳超时，判定掉线")
                _reset_session(state, "heartbeat_timeout")
                return
        except Exception as e:
            print(f"  ❤️ {state.name}: 心跳异常: {e}")
            state._hb_missed += 1
            if state._hb_missed >= HEARTBEAT_TIMEOUT:
                _reset_session(state, "heartbeat_timeout")
                return

        await asyncio.sleep(HEARTBEAT_INTERVAL)


def _reset_session(state: AgentLinkState, reason: str,
                   peer_frames_sent: int = 0, peer_frames_received: int = 0):
    """清理会话状态，写入历史"""
    if state.session_id is None:
        return

    # 保存 session_id 和 peer_url（触发 on_hangup 后会被清掉）
    _sid = state.session_id
    _purl = state.peer_url
    _pname = state.peer_name

    # 先写入历史
    rec = SessionRecord(
        session_id=_sid,
        peer_did=state.peer_did or "",
        peer_name=_pname or "",
        start_time=state.start_time,
        frames_sent=state.frames_sent,
        frames_received=state.frames_received,
        reason=reason,
    )
    rec.end_time = time.time()
    if state.history:
        asyncio.ensure_future(state.add_history(rec))
    else:
        asyncio.create_task(state.add_history(rec))

    print(f"\n🔌 {state.name}: 会话已断开 (时长: {rec.duration_sec}s, 收发: {rec.frames_sent}/{rec.frames_received}, 原因: {reason})")

    # 清理 WS
    if state.ws_conn:
        asyncio.ensure_future(state.ws_conn.close())
        state.ws_conn = None
    if state._hb_task:
        state._hb_task.cancel()
        state._hb_task = None

    if state.on_hangup:
        # 传显式参数，不等闭包捕获
        async def _do_hangup():
            await state.on_hangup(reason, _sid, _purl, _pname)
        asyncio.ensure_future(_do_hangup())

    state.status = AgentStatus.IDLE
    state.session_id = None
    state.peer_did = None
    state.peer_name = None
    state.peer_ws = None
    state.start_time = 0.0
    state.frames_sent = 0
    state.frames_received = 0
    state.seq = 0
    state._hb_missed = 0


# ═══════════════════════════════════════════════
# P1: 客户端（呼叫发起方）
# ═══════════════════════════════════════════════

class AgentLinkClient:
    """完整的 AgentLink 客户端封装"""

    def __init__(self, state: AgentLinkState):
        self.me = state
        self.http = httpx.AsyncClient()
        self._ws: Optional[any] = None
        self._recv_queue: asyncio.Queue = asyncio.Queue()
        self._recv_task: Optional[asyncio.Task] = None
        self._running = False

    async def call(self, target_url: str, target_name: str, capabilities: dict = None) -> bool:
        """发起呼叫 — HTTP 信令"""
        session_id = str(uuid.uuid4())
        self.me.session_id = session_id
        self.me.peer_did = f"did:wba:{target_url.replace('http://', '').replace(':', '-')}"
        self.me.peer_name = target_name
        self.me.start_time = time.time()

        payload = {
            "jsonrpc": "2.0",
            "method": "agentlink.call",
            "params": {
                "meta": {
                    "profile": "agentlink.session.v1",
                    "sender_did": self.me.did,
                    "target_did": self.me.peer_did,
                },
                "body": {
                    "session_id": session_id,
                    "caller_name": self.me.name,
                    "caller_url": self.me.http_url,
                    "caller_ws": f"{self.me.ws_url}/{session_id}",
                    "capabilities": capabilities or {
                        "stream_types": ["text", "json"],
                        "heartbeat_interval": HEARTBEAT_INTERVAL,
                    },
                }
            }
        }

        print(f"\n📞 {self.me.name}: 正在呼叫 {target_name} @ {target_url}")
        try:
            resp = await self.http.post(f"{target_url}/agentlink/call", json=payload, timeout=5)
            result = resp.json().get("result", {})

            if result.get("type") == "ring":
                print(f"  📞 {self.me.name}: 对方振铃中 (session={session_id[:8]}...)")
                peer_ws = result.get("ws_url", "")
                if peer_ws:
                    self.me.peer_ws = peer_ws
                return True
            elif result.get("type") == "busy":
                print(f"  ❌ {self.me.name}: {target_name} 占线 (在跟 {result.get('in_session_with', '某人')} 通话)")
                _reset_session(self.me, "peer_busy")
                return False
            else:
                print(f"  ❌ 呼叫失败: {result}")
                _reset_session(self.me, "call_failed")
                return False
        except httpx.TimeoutException:
            print(f"  ❌ {self.me.name}: 呼叫超时")
            _reset_session(self.me, "timeout")
            return False

    async def accept(self, session_id: str = None) -> bool:
        """接受呼入"""
        sid = session_id or self.me.session_id
        if not sid:
            return False

        payload = {
            "jsonrpc": "2.0",
            "method": "agentlink.accept",
            "params": {
                "meta": {"profile": "agentlink.session.v1", "sender_did": self.me.did},
                "body": {"session_id": sid, "accepted_at": time.strftime("%H:%M:%S")},
            }
        }
        resp = await self.http.post(f"{self.me.http_url}/agentlink/accept", json=payload, timeout=5)
        result = resp.json().get("result", {})
        if result.get("status") == "accepted":
            print(f"  ✅ {self.me.name}: 接受连接 — 与 {self.me.peer_name} 会话中")
            self.me.status = AgentStatus.IN_SESSION
            return True
        return False

    async def connect_ws(self) -> bool:
        """连接 WebSocket"""
        if not self.me.session_id:
            return False
        ws_url = self.me.peer_ws or f"{self.me.ws_url.replace('/agentlink/ws/', '').replace(str(self.me.port), '')}/{self.me.session_id}"
        # Build WS URL to peer
        peer_url = self.me.peer_ws or ws_url
        return await self._ws_connect(peer_url)

    async def _ws_connect(self, url: str) -> bool:
        try:
            import websockets
            self._ws = await websockets.connect(url)
            self.me.ws_conn = WSConnection()
            self.me.ws_conn.set_client(self._ws)
            self._running = True
            print(f"  🔗 {self.me.name}: WebSocket 已连接 ({url[:50]}...)")

            # 启动心跳
            if self.me._hb_task:
                self.me._hb_task.cancel()
            self.me._hb_task = asyncio.create_task(_heartbeat_loop(self.me))

            return True
        except Exception as e:
            print(f"  ⚠️ {self.me.name}: WebSocket 连接失败: {e}")
            return False

    async def send_data(self, text: str) -> bool:
        """发送数据帧（通过 WebSocket）"""
        if not self.me.ws_conn or not self.me.ws_conn.connected:
            return False
        seq = self.me.next_seq()
        msg = ws_message("agentlink.data", self.me, {
            "seq": seq,
            "type": "text",
            "payload": text,
        })
        try:
            await self.me.ws_conn.send_json(msg)
            self.me.frames_sent += 1
            self.me.tlog("data_tx", f"[{seq}] text {text[:60]}", self.me.session_id)
            print(f"  📤 {self.me.name} [{seq}] 发送 \"{text[:60]}\"")
            return True
        except Exception as e:
            print(f"  ⚠️ 发送失败 [{seq}]: {e}")
            return False

    async def send_json(self, obj: dict) -> bool:
        """发送 JSON 数据帧"""
        if not self.me.ws_conn or not self.me.ws_conn.connected:
            return False
        seq = self.me.next_seq()
        msg = ws_message("agentlink.data", self.me, {
            "seq": seq,
            "type": "json",
            "payload": json.dumps(obj, ensure_ascii=False),
        })
        try:
            await self.me.ws_conn.send_json(msg)
            self.me.frames_sent += 1
            self.me.tlog("data_tx", f"[{seq}] json", self.me.session_id)
            print(f"  📤 {self.me.name} [{seq}] 发送 JSON")
            return True
        except Exception as e:
            print(f"  ⚠️ 发送失败 [{seq}]: {e}")
            return False

    async def hangup(self, reason: str = "user_hangup"):
        """挂断会话"""
        if not self.me.peer_did:
            return

        duration = int(time.time() - self.me.start_time) if self.me.start_time else 0

        # 通知对方
        payload = {
            "jsonrpc": "2.0",
            "method": "agentlink.hangup",
            "params": {
                "meta": {
                    "profile": "agentlink.session.v1",
                    "session_id": self.me.session_id or "",
                },
                "body": {
                    "initiator": "local",
                    "reason": reason,
                    "duration_sec": duration,
                    "frames_sent": self.me.frames_sent,
                    "frames_received": self.me.frames_received,
                }
            }
        }
        try:
            peer_http = self.me.http_url.replace(str(self.me.port),
                                                  str(self.me.peer_did).split("-")[-1]
                                                  if "-" in (self.me.peer_did or "") else "18764")
            # 直接收 HTTP 发 hangup 给 peer
            await self.http.post(
                self.me.http_url.replace(f":{self.me.port}",
                                         f":{18764}" if "18763" in self.me.http_url else ":18763"),
                # 等 demo 里处理更干净
            )
        except Exception:
            pass

        # 清理本地
        _reset_session(self.me, reason)

    async def disconnect(self):
        """断开所有连接"""
        self._running = False
        if self._ws:
            await self._ws.close()
            self._ws = None
        if self.me.ws_conn:
            await self.me.ws_conn.close()
            self.me.ws_conn = None
        await self.http.aclose()
