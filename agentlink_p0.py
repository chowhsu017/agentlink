"""
AgentLink P0 Demo — 通联会话生命周期
本机双进程：Agent Alice(18763) → Agent Bob(18764)
"""
from __future__ import annotations
import asyncio, json, uuid, time
from dataclasses import dataclass, field, asdict
from typing import Optional
from fastapi import FastAPI, Request
import httpx

# ─── 数据模型 ─────────────────────────────────────

@dataclass
class CallRequest:
    session_id: str
    caller_did: str
    caller_name: str
    caller_url: str
    capabilities: dict = field(default_factory=lambda: {
        "stream_types": ["text", "json"],
        "heartbeat_interval_sec": 30,
        "e2ee": False,
    })
    context: dict = field(default_factory=dict)

@dataclass
class RingResponse:
    session_id: str
    ring_at: str
    timeout_sec: int = 30

@dataclass
class AcceptResponse:
    session_id: str
    accepted_at: str
    selected_stream: str = "text"

@dataclass
class RejectResponse:
    session_id: str
    reason: str = "busy"

@dataclass
class DataFrame:
    session_id: str
    seq: int
    type: str = "text"  # text | json
    payload: str = ""

@dataclass
class Heartbeat:
    session_id: str
    seq: int
    timestamp: str

@dataclass
class Hangup:
    session_id: str
    initiator: str = "local"  # local | remote | timeout
    reason: str = "user_hangup"
    duration_sec: int = 0
    frames_sent: int = 0
    frames_received: int = 0


# ─── Agent 类 ─────────────────────────────────────

class AgentLinkState:
    """单 agent 的会话状态"""
    def __init__(self, name: str, port: int, did: str):
        self.name = name
        self.port = port
        self.did = did
        self.url = f"http://localhost:{port}"

        # 当前会话
        self.session_id: Optional[str] = None
        self.peer_url: Optional[str] = None
        self.peer_name: Optional[str] = None
        self.status: str = "idle"  # idle | ringing | in_session
        self.start_time: float = 0.0
        self.frames_sent = 0
        self.frames_received = 0
        self.seq = 0

        # 历史
        self.history: list[dict] = []

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def to_json(self):
        return {
            "name": self.name,
            "did": self.did,
            "url": self.url,
            "status": self.status,
            "session_id": self.session_id,
            "peer": self.peer_name,
            "frames": {"sent": self.frames_sent, "received": self.frames_received},
        }


def _extract(data: dict, key: str, default=None):
    """从 ANP 格式的嵌套结构中提取 params.meta 或 params.body 的字段"""
    p = data.get("params", {})
    inner = p.get(key, {})
    return inner or default

def create_agent_app(state: AgentLinkState):
    """创建 FastAPI app，注入 agent 状态"""

    app = FastAPI(title=f"AgentLink - {state.name}")

    def _meta(data): return data.get("params", {}).get("meta", {})
    def _body(data): return data.get("params", {}).get("body", {})

    # ─── 呼叫 ───

    @app.post("/agentlink/call")
    async def handle_call(req: Request):
        data = await req.json()
        meta = _meta(data)
        body = _body(data)
        session_id = body.get("session_id", str(uuid.uuid4()))
        caller_name = body.get("caller_name", "Unknown")
        caller_url = body.get("caller_url", "")

        if state.status == "in_session":
            return {"jsonrpc": "2.0", "result": {
                "type": "busy",
                "session_id": session_id,
                "in_session_with": state.peer_name,
            }}

        # 振铃
        state.status = "ringing"
        state.session_id = session_id
        state.peer_url = caller_url
        state.peer_name = caller_name
        state.start_time = time.time()

        print(f"\n📞 {state.name}: 收到来自 {caller_name} 的呼叫 (session={session_id[:8]}...)")

        return {"jsonrpc": "2.0", "result": {
            "type": "ring",
            "session_id": session_id,
            "ring_at": time.strftime("%H:%M:%S"),
            "timeout_sec": 30,
        }}

    # ─── 接受呼叫的回复 ───

    @app.post("/agentlink/accept")
    async def handle_accept(req: Request):
        data = await req.json()
        session_id = _body(data).get("session_id", "")

        if state.session_id != session_id:
            return {"jsonrpc": "2.0", "error": {"code": -1, "message": "session mismatch"}}

        state.status = "in_session"
        print(f"\n📞 {state.name}: 呼叫已接通！与 {state.peer_name} 会话中")

        return {"jsonrpc": "2.0", "result": {"status": "accepted"}}

    # ─── 数据帧 ───

    @app.post("/agentlink/data")
    async def handle_data(req: Request):
        data = await req.json()
        meta = _meta(data)
        body = _body(data)
        sid = meta.get("session_id", "")
        payload = body.get("payload", "")
        seq = body.get("seq", 0)
        dtype = body.get("type", "text")

        if state.session_id != sid:
            return {"jsonrpc": "2.0", "error": {"code": -1, "message": f"session mismatch: {state.session_id} != {sid}"}}

        state.frames_received += 1
        print(f"  📨 {state.name} [{seq}] 收到: \"{payload[:60]}\"")

        return {"jsonrpc": "2.0", "result": {"status": "ok", "seq": seq}}

    # ─── 挂断 ───

    @app.post("/agentlink/hangup")
    async def handle_hangup(req: Request):
        data = await req.json()
        body = _body(data)
        sid = _meta(data).get("session_id", "")

        if state.session_id == sid:
            duration = int(time.time() - state.start_time)
            state.history.append({
                "session_id": state.session_id,
                "peer": state.peer_name,
                "duration_sec": duration,
                "frames_sent": state.frames_sent,
                "frames_received": state.frames_received,
                "reason": body.get("reason", "remote_hangup"),
            })
            print(f"\n🔌 {state.name}: 会话已断开 (时长: {duration}s, 收发: {state.frames_sent}/{state.frames_received})")
            state.status = "idle"
            state.session_id = None
            state.peer_url = None
            state.peer_name = None
            state.start_time = 0.0

        return {"jsonrpc": "2.0", "result": {"status": "hungup"}}

    # ─── 状态查询 ───

    @app.get("/status")
    async def get_status():
        return state.to_json()

    @app.get("/history")
    async def get_history():
        return state.history

    return app


# ─── Alice 的呼叫控制 ───────────────────────────

class AgentLinkCaller:
    """发起呼叫的客户端"""

    def __init__(self, self_state: AgentLinkState):
        self.me = self_state
        self.client = httpx.AsyncClient()

    async def call(self, target_url: str, target_name: str):
        """发起呼叫"""
        session_id = str(uuid.uuid4())
        self.me.session_id = session_id
        self.me.peer_url = target_url
        self.me.peer_name = target_name
        self.me.start_time = time.time()

        payload = {
            "jsonrpc": "2.0",
            "method": "agentlink.call",
            "params": {
                "meta": {
                    "profile": "agentlink.session.v1",
                    "sender_did": self.me.did,
                    "target_did": f"did:wba:localhost:{18764}",
                },
                "body": {
                    "session_id": session_id,
                    "caller_name": self.me.name,
                    "caller_url": self.me.url,
                    "capabilities": {"stream_types": ["text", "json"]},
                }
            }
        }

        print(f"\n📞 {self.me.name}: 正在呼叫 {target_name} @ {target_url}")
        resp = await self.client.post(f"{target_url}/agentlink/call", json=payload)
        result = resp.json().get("result", {})

        if result.get("type") == "ring":
            print(f"  📞 {self.me.name}: 对方振铃中 (session={session_id[:8]}...)")
            return True
        elif result.get("type") == "busy":
            print(f"  ❌ {self.me.name}: 对方占线")
            self.me.status = "idle"
            return False
        else:
            print(f"  ❌ 呼叫失败: {result}")
            self.me.status = "idle"
            return False

    async def wait_accept(self, timeout: float = 10.0):
        """等待对方接受（通过 webhook 回调模拟）"""
        start = time.time()
        while time.time() - start < timeout:
            resp = await self.client.get(f"{self.me.url}/status")
            st = resp.json()
            if st.get("status") == "in_session":
                self.me.status = "in_session"
                self.me.start_time = time.time()
                return True
            await asyncio.sleep(0.5)
        return False

    async def send_data(self, text: str):
        """发送数据帧"""
        if not self.me.peer_url or not self.me.session_id:
            return False
        seq = self.me.next_seq()
        payload = {
            "jsonrpc": "2.0",
            "method": "agentlink.data",
            "params": {
                "meta": {
                    "profile": "agentlink.session.v1",
                    "session_id": self.me.session_id,
                },
                "body": {
                    "seq": seq,
                    "type": "text",
                    "payload": text,
                }
            }
        }
        resp = await self.client.post(f"{self.me.peer_url}/agentlink/data", json=payload)
        j = resp.json()
        result = j.get("result", {})
        if result.get("status") == "ok":
            self.me.frames_sent += 1
            print(f"  📤 {self.me.name} [{seq}] 发送 \"{text[:60]}\"")
            return True
        else:
            print(f"  ⚠️ 发送失败 [{seq}]: {result}")
            return False

    async def hangup(self, reason: str = "user_hangup"):
        """挂断"""
        if not self.me.peer_url:
            return
        duration = int(time.time() - self.me.start_time) if self.me.start_time else 0

        payload = {
            "jsonrpc": "2.0",
            "method": "agentlink.hangup",
            "params": {
                "meta": {
                    "profile": "agentlink.session.v1",
                    "session_id": self.me.session_id,
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
        await self.client.post(f"{self.me.peer_url}/agentlink/hangup", json=payload)

        # 本方也清理
        self.me.history.append({
            "session_id": self.me.session_id,
            "peer": self.me.peer_name,
            "duration_sec": duration,
            "frames_sent": self.me.frames_sent,
            "frames_received": self.me.frames_received,
            "reason": reason,
        })
        print(f"\n🔌 {self.me.name}: 主动挂断 (时长: {duration}s, 收发: {self.me.frames_sent}/{self.me.frames_received})")
        self.me.status = "idle"
        self.me.session_id = None
        self.me.peer_url = None
        self.me.peer_name = None
        self.me.start_time = 0.0
