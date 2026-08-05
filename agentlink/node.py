"""
AgentLink P2 — 频道广播 + Presence 在线状态

P1→P2 升级:
  1. 频道订阅/广播：channel.subscribe + channel.broadcast
  2. Presence：presence.update + 查询
  3. ChannelHub：进程内频道消息路由

架构:
  - ChannelHub: 单例，管理 channel_id → [WsAdapter] 映射
  - HTTP POST /agentlink/channel/subscribe: Agent 订阅频道
  - HTTP POST /agentlink/channel/broadcast: 向频道广播消息
  - HTTP POST /agentlink/presence/update: 更新在线状态
  - HTTP GET /agentlink/presence: 查询所有节点在线状态

基于 P1 agentlink_p1.py — 完整的 P1+P2 融合版本。
"""
from __future__ import annotations
import asyncio, json, uuid, time, os, subprocess
from dataclasses import dataclass
from typing import Optional, Callable, Any, Dict, Set
from collections import defaultdict

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
import httpx

# ─── 簿记埋点（opt-in）──────────────────────────────
# 环境变量 AGENTLINK_BOOKKEEP=1 启用外部簿记脚本

_bookkeep_script = os.environ.get("AGENTLINK_BOOKKEEP_SCRIPT", "")
BOOKKEEP_ENABLED = bool(_bookkeep_script) and os.path.exists(_bookkeep_script)

def _bookkeep(cmd: str, *args):
    if not BOOKKEEP_ENABLED:
        return
    try:
        subprocess.run(
            ["python3", _bookkeep_script, cmd] + [str(a) for a in args],
            capture_output=True, timeout=3
        )
    except Exception:
        pass


# ─── 数据模型 ─────────────────────────────────────

@dataclass
class SessionRecord:
    session_id: str
    peer_name: str
    started_at: float
    ended_at: float = 0.0
    frames_sent: int = 0
    frames_received: int = 0
    heartbeats_sent: int = 0
    heartbeats_received: int = 0
    disconnects: int = 0
    reason: str = ""
    status: str = "spawned"


# ─── ChannelHub ───────────────────────────────────

class ChannelHub:
    """
    进程内频道消息路由。
    单例模式，跨所有 AgentLinkNode 共享。
    
    P2 采用 HTTP 推送模式：订阅者注册 callback URL，广播时 Hub 向所有 URL POST 消息。
    无需 ws 连接即可订阅。
    """
    _instance: Optional[ChannelHub] = None

    def __init__(self):
        # channel_id → set of (node_id, callback_url)
        self._channels: Dict[str, Set[tuple]] = defaultdict(set)
        # node_id → presence info
        self._presence: Dict[str, dict] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = ChannelHub()
        return cls._instance

    async def subscribe(self, channel_id: str, node_id: str, callback_url: str):
        async with self._lock:
            self._channels[channel_id].add((node_id, callback_url))
        print(f"  📻 [{node_id}] 订阅频道 {channel_id} ← {callback_url}")

    async def unsubscribe(self, channel_id: str, node_id: str):
        async with self._lock:
            existing = self._channels.get(channel_id, set())
            self._channels[channel_id] = {p for p in existing if p[0] != node_id}
        print(f"  📻 [{node_id}] 退订频道 {channel_id}")

    async def broadcast(self, channel_id: str, msg: dict, sender: str):
        """向频道所有订阅者 HTTP POST 广播消息"""
        async with self._lock:
            subscribers = list(self._channels.get(channel_id, set()))
        delivered = 0
        async with httpx.AsyncClient(timeout=3) as c:
            for node_id, url in subscribers:
                if node_id == sender:
                    continue  # 不发给发送者自己
                try:
                    await c.post(f"{url}/agentlink/channel/on_message", json=msg)
                    delivered += 1
                except Exception:
                    pass
        if delivered > 0:
            print(f"  📢 [{sender}] 频道 {channel_id} → {delivered} 个订阅者")
        return delivered

    async def set_presence(self, node_id: str, info: dict):
        async with self._lock:
            self._presence[node_id] = {**info, "updated_at": time.strftime("%H:%M:%S")}

    async def get_presence(self):
        async with self._lock:
            return dict(self._presence)

    async def remove_presence(self, node_id: str):
        async with self._lock:
            self._presence.pop(node_id, None)


# ─── WsAdapter ─────────────────────────────────────

class WsAdapter:
    """统一封装 websockets-client 和 FastAPI WebSocket"""
    def __init__(self, raw: Any):
        self._raw = raw
        self._lock = asyncio.Lock()

    async def send(self, msg: dict):
        text = json.dumps(msg, ensure_ascii=False)
        async with self._lock:
            r = self._raw
            if hasattr(r, 'send_text'):
                await r.send_text(text)
            elif hasattr(r, 'send'):
                await r.send(text)
            else:
                await r.send_json(msg)

    async def recv(self) -> dict:
        r = self._raw
        if hasattr(r, 'receive_text'):
            raw = await r.receive_text()
        elif hasattr(r, 'recv'):
            raw = await r.recv()
        else:
            raise RuntimeError(f"Unknown ws type: {type(r)}")
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return json.loads(raw)

    async def close(self):
        try:
            await self._raw.close()
        except Exception:
            pass

    @property
    def raw(self):
        return self._raw


# ─── AgentLinkNode (P2 enhanced) ──────────────────

class AgentLinkNode:
    HEARTBEAT_INTERVAL = 30
    HEARTBEAT_MISS_THRESHOLD = 3
    RECONNECT_MAX = 5
    RECONNECT_BASE_DELAY = 1.0

    def __init__(self, name: str, port: int, did: str = ""):
        self.name = name
        self.port = port
        self.did = did or f"did:wba:localhost:{port}"
        self.url = f"http://localhost:{port}"
        self.ws_url = f"ws://localhost:{port}/agentlink/ws"

        # 会话状态
        self.session_id: Optional[str] = None
        self.peer_url: Optional[str] = None
        self.peer_name: Optional[str] = None
        self.peer_ws_url: Optional[str] = None
        self.status: str = "idle"

        # 连接
        self._ws: Optional[WsAdapter] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._sender_task: Optional[asyncio.Task] = None
        self._should_reconnect = False
        self._connecting = False

        # 统计
        self.seq = 0
        self.frames_sent = 0
        self.frames_received = 0
        self._heartbeat_sent = 0
        self._heartbeat_received = 0
        self._disconnects = 0
        self._heartbeat_missed = 0
        self.start_time: float = 0.0

        # P2: 频道订阅
        self._channels: Set[str] = set()
        self._channel_hub = ChannelHub.get()

        # 消息队列
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.history: list[SessionRecord] = []

        # Presence
        self._presence_status: str = "offline"

        # 回调
        self.on_message: Optional[Callable] = None
        self.on_state_change: Optional[Callable] = None

    # ─── 状态 ───

    def to_json(self):
        return {
            "name": self.name, "status": self.status,
            "session_id": self.session_id, "peer": self.peer_name,
            "frames": {"sent": self.frames_sent, "received": self.frames_received},
            "heartbeats": {"sent": self._heartbeat_sent, "received": self._heartbeat_received},
            "disconnects": self._disconnects,
            "channels": list(self._channels),
            "presence": self._presence_status,
        }

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    # ─── 频道操作 ───

    async def subscribe_channel(self, channel_id: str):
        """订阅频道（HTTP 模式，无需 ws 连接）"""
        await self._channel_hub.subscribe(channel_id, self.name, self.url)
        self._channels.add(channel_id)
        return True

    async def broadcast_to_channel(self, channel_id: str, payload: dict):
        """向频道广播"""
        msg = {
            "type": "channel_broadcast",
            "channel_id": channel_id,
            "sender": self.name,
            "payload": payload,
            "seq": self.next_seq(),
            "timestamp": time.strftime("%H:%M:%S"),
        }
        return await self._channel_hub.broadcast(channel_id, msg, self.name)

    # ─── 心跳 / Reader / Sender / 重连 / 呼叫 / 挂断 ───
    # （P1 逻辑不变，此处省略注释相同的代码）

    async def _cleanup(self):
        # 退订所有频道
        for ch in list(self._channels):
            await self._channel_hub.unsubscribe(ch, self.name)
        self._channels.clear()

        for t in [self._reader_task, self._sender_task]:
            if t and not t.done():
                t.cancel()
        self._reader_task = None
        self._sender_task = None
        self._should_reconnect = False
        self._heartbeat_missed = 0
        if self._ws:
            await self._ws.close()
        self._ws = None
        self._connecting = False

    def _log_start(self):
        if self.session_id:
            _bookkeep("register", self.session_id,
                f"agentlink:peer:{self.peer_name or '?'}",
                self.session_id[:8],
                f"AgentLink P2: {self.name} ↔ {self.peer_name}",
                f"agentlink-p2-{self.name.lower()}-{(self.peer_name or 'peer').lower()}",
                "agentlink-v2", "")

    def _log_end(self, reason: str):
        if self.session_id:
            d = int(time.time() - self.start_time) if self.start_time else 0
            _bookkeep("update", self.session_id, "completed",
                f"会话结束: {d}s, tx={self.frames_sent} rx={self.frames_received}, reconn={self._disconnects}, {reason}")

    async def hangup(self, reason: str = "user_hangup"):
        self._should_reconnect = False
        await self._do_hangup(reason)

    async def _do_hangup(self, reason: str):
        d = int(time.time() - self.start_time) if self.start_time else 0
        if self._ws:
            try:
                await self._ws.send({
                    "type": "hangup", "session_id": self.session_id,
                    "initiator": self.name, "reason": reason,
                    "duration_sec": d, "frames_sent": self.frames_sent,
                    "frames_received": self.frames_received,
                })
            except Exception:
                pass
        self.history.append(SessionRecord(
            session_id=self.session_id or "",
            peer_name=self.peer_name or "?", started_at=self.start_time,
            ended_at=time.time(), frames_sent=self.frames_sent,
            frames_received=self.frames_received,
            heartbeats_sent=self._heartbeat_sent,
            heartbeats_received=self._heartbeat_received,
            disconnects=self._disconnects, reason=reason,
            status="completed" if reason == "user_hangup" else reason,
        ))
        print(f"\n🔌 {self.name}: 断开 (时长={d}s, tx={self.frames_sent} rx={self.frames_received}, reconn={self._disconnects}, reason={reason})")
        self._log_end(reason)
        await self._cleanup()
        self.status = "idle"
        self.session_id = None
        self.peer_url = None
        self.peer_name = None
        self.peer_ws_url = None
        self.start_time = 0.0
        self._disconnects = 0
        if self.on_state_change:
            self.on_state_change("disconnected", reason)

    async def send_data(self, text: str) -> bool:
        if self.status != "in_session" or not self._ws:
            return False
        seq = self.next_seq()
        try:
            await self._ws.send({
                "type": "data", "session_id": self.session_id,
                "seq": seq, "payload": text,
            })
            self.frames_sent += 1
            print(f"  📤 {self.name} [{seq}] 「{text[:50]}」")
            return True
        except Exception as e:
            print(f"  ⚠️ {self.name}: 发送失败: {e}")
            return False

    async def _reader_loop(self):
        try:
            while self.status == "in_session" and self._ws:
                try:
                    msg = await asyncio.wait_for(
                        self._ws.recv(), timeout=self.HEARTBEAT_INTERVAL * 1.5
                    )
                except asyncio.TimeoutError:
                    self._heartbeat_missed += 1
                    if self._heartbeat_missed >= self.HEARTBEAT_MISS_THRESHOLD:
                        print(f"  ⏰ {self.name}: 心跳超时 ({self._heartbeat_missed}次)")
                        await self._do_hangup("timeout")
                        return
                    continue
                mt = msg.get("type", "")
                if mt == "heartbeat":
                    self._heartbeat_missed = 0
                    self._heartbeat_received += 1
                elif mt == "data":
                    self.frames_received += 1
                    payload = msg.get("payload", "")
                    print(f"  📨 {self.name} [{msg.get('seq',0)}] 「{payload[:50]}」")
                    await self.inbox.put(msg)
                    if self.on_message:
                        self.on_message(msg)
                elif mt == "channel_broadcast":
                    # P2: 频道广播帧
                    ch = msg.get("channel_id", "?")
                    sender = msg.get("sender", "?")
                    p = msg.get("payload", {})
                    print(f"  📻 {self.name} [频道:{ch}] 来自 {sender}: {p}")
                    await self.inbox.put(msg)
                    if self.on_message:
                        self.on_message(msg)
                elif mt == "hangup":
                    print(f"  🔌 {self.name}: 对端挂断")
                    await self._do_hangup("remote_hangup")
                    return
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"  ⚡ {self.name}: Reader 断开: {type(e).__name__}")
            if self.status == "in_session" and self.peer_ws_url and self._should_reconnect:
                asyncio.create_task(self._reconnect_loop())
            elif self.status == "in_session":
                await self._do_hangup("disconnected")

    async def _sender_loop(self):
        try:
            while self.status == "in_session":
                await asyncio.sleep(self.HEARTBEAT_INTERVAL)
                if self.status != "in_session":
                    break
                try:
                    await self._ws.send({
                        "type": "heartbeat",
                        "session_id": self.session_id,
                        "seq": self.next_seq(),
                        "timestamp": time.strftime("%H:%M:%S"),
                    })
                    self._heartbeat_sent += 1
                except Exception:
                    pass
        except asyncio.CancelledError:
            pass

    async def _reconnect_loop(self):
        if self._connecting:
            return
        self._connecting = True
        try:
            for attempt in range(1, self.RECONNECT_MAX + 1):
                if not self._should_reconnect:
                    return
                delay = self.RECONNECT_BASE_DELAY * (2 ** (attempt - 1))
                print(f"  🔄 {self.name}: 重连 {attempt}/{self.RECONNECT_MAX} ({delay:.0f}s后)...")
                await asyncio.sleep(delay)
                if not self._should_reconnect:
                    return
                try:
                    from websockets.client import connect as ws_connect
                    raw = await ws_connect(self.peer_ws_url,
                        extra_headers={"X-AgentLink-Session": self.session_id or ""},
                        max_size=2**20)
                    self._ws = WsAdapter(raw)
                    self._disconnects += 1
                    self._heartbeat_missed = 0
                    self._reader_task = asyncio.create_task(self._reader_loop())
                    self._sender_task = asyncio.create_task(self._sender_loop())
                    print(f"  ✅ {self.name}: 重连成功")
                    return
                except Exception as e:
                    print(f"  ⚠️ {self.name}: 重连失败: {e}")
            print(f"  ❌ {self.name}: 重连耗尽")
            await self._do_hangup("reconnect_failed")
            return
        finally:
            self._connecting = False

    async def call(self, target_ws_url: str, target_name: str,
                   target_http_url: str = "") -> bool:
        sid = str(uuid.uuid4())
        self.session_id = sid
        self.peer_name = target_name
        self.peer_url = target_http_url or target_ws_url.replace("ws://", "http://").rstrip("/ws")
        self.peer_ws_url = target_ws_url
        self.start_time = time.time()
        self.seq = 0
        self._disconnects = 0
        self.frames_sent = 0
        self.frames_received = 0
        self._heartbeat_sent = 0
        self._heartbeat_received = 0
        self._should_reconnect = True
        http = self.peer_url

        async with httpx.AsyncClient() as c:
            print(f"\n📞 {self.name} → {target_name} @ {http}")
            r = await c.post(f"{http}/agentlink/call", json={
                "jsonrpc": "2.0", "method": "agentlink.call",
                "params": {"meta": {"profile": "agentlink.session.v1"},
                           "body": {"session_id": sid, "caller_name": self.name,
                                    "caller_url": self.url,
                                    "caller_ws_url": self.ws_url,
                                    "capabilities": {"stream_types": ["text", "json"]}}}
            })
            if r.json().get("result", {}).get("type") != "ring":
                print(f"  ❌ 呼叫失败: {r.json()}")
                return False
            print(f"  📞 振铃中...")

        await asyncio.sleep(1)
        async with httpx.AsyncClient() as c:
            r = await c.post(f"{http}/agentlink/accept", json={
                "jsonrpc": "2.0", "method": "agentlink.accept",
                "params": {"meta": {"profile": "agentlink.session.v1"},
                           "body": {"session_id": sid, "accepted_at": "now"}}
            })
            if r.json().get("result", {}).get("status") != "accepted":
                print(f"  ❌ 对方未接受")
                return False

        try:
            from websockets.client import connect as ws_connect
            raw = await ws_connect(target_ws_url,
                extra_headers={"X-AgentLink-Session": sid}, max_size=2**20)
            self._ws = WsAdapter(raw)
        except Exception as e:
            print(f"  ❌ ws 连接失败: {e}")
            return False

        self.status = "in_session"
        self._heartbeat_missed = 0
        self._reader_task = asyncio.create_task(self._reader_loop())
        self._sender_task = asyncio.create_task(self._sender_loop())
        self._presence_status = "busy"
        await self._channel_hub.set_presence(self.name, {
            "status": "busy", "peer": target_name,
            "since": time.strftime("%H:%M:%S"),
        })
        self._log_start()
        print(f"  ✅ 会话建立: {self.name} ↔ {target_name}")
        return True

    async def wait_message(self, timeout: float = 5.0) -> Optional[dict]:
        try:
            return await asyncio.wait_for(self.inbox.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None


# ─── FastAPI App (P2 enhanced) ────────────────────

def create_agent_app(node: AgentLinkNode) -> FastAPI:
    app = FastAPI(title=f"AgentLink P2 - {node.name}")
    hub = ChannelHub.get()

    def _body(data): return data.get("params", {}).get("body", {})

    # ─── P1: 信令 ───

    @app.post("/agentlink/call")
    async def handle_call(req: Request):
        data = await req.json()
        body = _body(data)
        sid = body.get("session_id", str(uuid.uuid4()))
        caller_name = body.get("caller_name", "?")
        caller_url = body.get("caller_url", "")
        caller_ws = body.get("caller_ws_url", "")

        if node.status == "in_session":
            return {"jsonrpc": "2.0", "result": {"type": "busy", "session_id": sid}}

        node.status = "ringing"
        node.session_id = sid
        node.peer_url = caller_url
        node.peer_name = caller_name
        node.peer_ws_url = caller_ws
        node.start_time = time.time()
        print(f"\n📞 {node.name}: 来自 {caller_name} 的呼叫")
        return {"jsonrpc": "2.0", "result": {"type": "ring", "session_id": sid, "ring_at": time.strftime("%H:%M:%S")}}

    @app.post("/agentlink/accept")
    async def handle_accept(req: Request):
        sid = _body(await req.json()).get("session_id", "")
        if node.session_id != sid:
            return {"jsonrpc": "2.0", "error": {"code": -1, "message": "session mismatch"}}
        node.status = "in_session"
        node._heartbeat_missed = 0
        node._presence_status = "busy"
        await hub.set_presence(node.name, {
            "status": "busy", "peer": node.peer_name,
            "since": time.strftime("%H:%M:%S"),
        })
        node._log_start()
        print(f"📞 {node.name}: 已接通 {node.peer_name}")
        return {"jsonrpc": "2.0", "result": {"status": "accepted"}}

    @app.websocket("/agentlink/ws")
    async def handle_ws(websocket: WebSocket):
        """WebSocket 连接——强制校验 session_id 防止会话劫持"""
        # 读取连接时附带的查询参数: ws://host/agentlink/ws?session_id=xxx&did=xxx
        qs_session = websocket.query_params.get("session_id", "")
        qs_did = websocket.query_params.get("did", "")

        # 必须提供 session_id 且匹配当前会话
        if not node.session_id:
            await websocket.close(code=4003, reason="no active session")
            return
        if not qs_session or qs_session != node.session_id:
            await websocket.close(code=4001, reason="session_id required and must match")
            return
        # did 校验：如果 ws 带了 did，必须匹配会话对端
        if qs_did and node.peer_name and qs_did != node.peer_name:
            await websocket.close(code=4002, reason="did mismatch")
            return

        await websocket.accept()
        node._ws = WsAdapter(websocket)

        if not node._sender_task or node._sender_task.done():
            node._sender_task = asyncio.create_task(node._sender_loop())
        if not node._reader_task or node._reader_task.done():
            node._reader_task = asyncio.create_task(node._reader_loop())

        try:
            while node.status in ("ringing", "in_session") and node._ws:
                await asyncio.sleep(5)
        except asyncio.CancelledError:
            pass
        print(f"  🔚 {node.name}: ws handler 退出")

    # ─── P2: 频道 ───

    @app.post("/agentlink/channel/subscribe")
    async def handle_channel_subscribe(req: Request):
        channel_id = _body(await req.json()).get("channel_id", "")
        if not channel_id:
            return {"status": "error", "message": "channel_id required"}
        await node.subscribe_channel(channel_id)
        return {"status": "ok", "channel_id": channel_id, "subscriber": node.name}

    @app.post("/agentlink/channel/broadcast")
    async def handle_channel_broadcast(req: Request):
        data = await req.json()
        body = _body(data)
        channel_id = body.get("channel_id", "")
        payload = body.get("payload", {})
        delivered = await node.broadcast_to_channel(channel_id, payload)
        return {"status": "ok", "delivered": delivered}

    @app.post("/agentlink/channel/on_message")
    async def handle_channel_message(req: Request):
        """接收频道广播消息（Hub 推送到此端点）"""
        msg = await req.json()
        ch = msg.get("channel_id", "?")
        sender = msg.get("sender", "?")
        payload = msg.get("payload", {})
        print(f"  📻 {node.name} [频道:{ch}] 来自 {sender}: {payload}")
        await node.inbox.put(msg)
        if node.on_message:
            node.on_message(msg)
        return {"status": "ok"}

    # ─── P2: Presence ───

    @app.post("/agentlink/presence/update")
    async def handle_presence_update(req: Request):
        body = _body(await req.json())
        node._presence_status = body.get("status", "idle")
        await hub.set_presence(node.name, {
            "status": node._presence_status,
            "peer": body.get("peer"),
            "since": time.strftime("%H:%M:%S"),
            "capabilities": body.get("capabilities", {}),
        })
        return {"status": "ok", "node": node.name, "presence": node._presence_status}

    @app.get("/agentlink/presence")
    async def handle_presence_get():
        return await hub.get_presence()

    # ─── 状态查询 ───

    @app.get("/status")
    async def get_status():
        return node.to_json()

    @app.get("/history")
    async def get_history():
        return [{
            "session_id": r.session_id, "peer_name": r.peer_name,
            "started_at": r.started_at, "ended_at": r.ended_at,
            "frames_sent": r.frames_sent, "frames_received": r.frames_received,
            "heartbeats_sent": r.heartbeats_sent, "heartbeats_received": r.heartbeats_received,
            "disconnects": r.disconnects, "reason": r.reason, "status": r.status,
        } for r in node.history]

    return app
