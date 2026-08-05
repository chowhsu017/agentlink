from __future__ import annotations
import asyncio, time
from dataclasses import dataclass, field
from typing import Optional, Callable
from enum import Enum

class AgentStatus(Enum):
    IDLE = "idle"; RINGING = "ringing"; IN_SESSION = "in_session"
    AWAY = "away"; INVISIBLE = "invisible"

@dataclass
class TimelineEvent:
    agent: str; event_type: str; detail: str = ""
    ts: float = field(default_factory=time.time); session_id: str = ""
    def ts_str(self): return time.strftime("%H:%M:%S", time.localtime(self.ts))
    def to_dict(self): return {"agent":self.agent,"event":self.event_type,"detail":self.detail,"ts":round(self.ts,3),"ts_str":self.ts_str(),"session_id":self.session_id}

@dataclass
class SessionRecord:
    session_id:str="";peer_did:str="";peer_name:str="";start_time:float=0.0;end_time:float=0.0
    frames_sent:int=0;frames_received:int=0;reason:str=""
    @property
    def duration_sec(self): return int(self.end_time-self.start_time) if self.start_time and self.end_time else 0
    def to_dict(self): return {"session_id":self.session_id,"peer_did":self.peer_did,"peer_name":self.peer_name,"duration_sec":self.duration_sec,"frames_sent":self.frames_sent,"frames_received":self.frames_received,"reason":self.reason}

class AgentLinkState:
    def __init__(self, name:str, port:int, did:str):
        self.name=name;self.port=port;self.did=did
        self.http_url=f"http://localhost:{port}";self.ws_url=f"ws://localhost:{port}/agentlink/ws";self.peer_url=f"http://localhost:{port}"
        self.session_id=None;self.peer_did=None;self.peer_name=None;self.peer_ws=None
        self.status=AgentStatus.IDLE;self.start_time=0.0;self.frames_sent=0;self.frames_received=0;self.seq=0
        self._hb_missed=0;self._hb_task=None;self.history=[];self.timeline=[]
        self.channels={};self.presence_status={};self._presence_clients={}
        self._history_lock=asyncio.Lock();self._timeline_lock=asyncio.Lock();self._timeline_queue=asyncio.Queue()
        self.ws_conn=None;self._call_context={};self._session_salt=None
        self.on_ring=None;self.on_accept=None;self.on_hangup=None;self.on_data=None
    def next_seq(self): self.seq+=1;return self.seq
    def to_dict(self): return {"name":self.name,"did":self.did,"url":self.http_url,"status":self.status.value,"session_id":self.session_id,"peer":self.peer_name,"frames":{"sent":self.frames_sent,"received":self.frames_received}}
    def tlog(self, event_type, detail='', session_id=''): pass
    async def add_history(self, rec): self.history.append(rec)

# ─── 工具函数 ──────────────────────────────

def rpc_result(payload: dict) -> dict:
    return {"jsonrpc": "2.0", "result": payload}

def rpc_error(code: int, msg: str) -> dict:
    return {"jsonrpc": "2.0", "error": {"code": code, "message": msg}}

def ws_message(method: str, state, body: dict) -> dict:
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
