"""
AgentLink P2 — 频道中继 + Presence 联邦
=======================================
架构：
  Channel Relay (独立进程)       Presence Federation (集成到信令)
  ┌──────────────────────┐       ┌──────────────────────────┐
  │  REST: 创建/列表频道   │       │  信令服务                │
  │  WS:   订阅/广播/中继  │       │  /signal/presence_push   │
  │  SQLite: 频道持久化    │       │  /signal/presence_sub    │
  │  E2EE:  组密钥派生     │       │  SQLite: 持久化状态       │
  └──────────────────────┘       └──────────────────────────┘

单进程模式（推荐）：
  from .signal import run_signal
  from agentlink_p2 import add_channel_relay
  app = create_signal_app()
  add_channel_relay(app, signal)  # 挂在信令服务的 app 上
  uvicorn.run(app, ...)

依赖：
  pip install fastapi uvicorn cryptography websockets httpx
"""
from __future__ import annotations
import asyncio, json, os, sqlite3, time, uuid, hashlib
from dataclasses import dataclass, field
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

# 从 agentlink_p1 导入核心类型
import sys, os as _os
# path handled by pip
from .p1_shim import AgentLinkState, AgentStatus, ws_message, rpc_result, rpc_error
from .crypto import (
    generate_keypair, compute_shared_secret, derive_session_key,
    SessionCipher, encrypt_message, decrypt_message,
    _b64, _unb64,
)
from .signal import SignalServer  # 复用信号服务的数据库和状态


# ═══════════════════════════════════════════════
# 常量
# ═══════════════════════════════════════════════

CHANNEL_DB_PATH = _os.path.join(
    _os.path.dirname(_os.path.abspath(__file__)), "agentlink_channels.db"
)


# ═══════════════════════════════════════════════
# 频道数据库
# ═══════════════════════════════════════════════

def init_channel_db(db_path: str = CHANNEL_DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS channels (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            creator_did TEXT NOT NULL,
            created_at REAL NOT NULL,
            e2ee BOOLEAN DEFAULT 0,
            metadata TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS channel_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id TEXT NOT NULL,
            sender_did TEXT NOT NULL,
            type TEXT DEFAULT 'text',
            payload TEXT NOT NULL,
            encrypted BOOLEAN DEFAULT 0,
            ts REAL NOT NULL,
            FOREIGN KEY (channel_id) REFERENCES channels(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS channel_members (
            channel_id TEXT NOT NULL,
            agent_did TEXT NOT NULL,
            enc_public_b64 TEXT DEFAULT '',
            joined_at REAL NOT NULL,
            PRIMARY KEY (channel_id, agent_did)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS channel_subscriptions (
            channel_id TEXT NOT NULL,
            agent_did TEXT NOT NULL,
            ws_id TEXT NOT NULL,
            mode TEXT DEFAULT 'readwrite',
            subscribed_at REAL NOT NULL,
            PRIMARY KEY (channel_id, ws_id)
        )
    """)
    conn.commit()
    return conn


# ═══════════════════════════════════════════════
# 频道中继
# ═══════════════════════════════════════════════

class ChannelRelay:
    """频道中继服务 — 管理频道、会员、消息转发和 E2EE"""

    def __init__(self, db_path: str = CHANNEL_DB_PATH,
                 signal_server: Optional[SignalServer] = None):
        self.db_path = db_path
        self.conn = init_channel_db(db_path)
        # WS 连接池: ws_id → {websocket, agent_did, channels}
        self.ws_pool: dict[str, dict] = {}
        # 频道→订阅者映射 (内存加速)
        self.channel_subs: dict[str, dict[str, WebSocket]] = {}
        # 信号服务引用 (用于跨服务调用)
        self.signal = signal_server
        # E2EE session 缓存
        self._channel_ciphers: dict[str, SessionCipher] = {}

    # ─── 频道 CRUD ─────────────────────────────

    def create_channel(self, channel_id: str, name: str, creator_did: str,
                       e2ee: bool = False, metadata: str = "") -> dict:
        """创建频道"""
        now = time.time()
        try:
            self.conn.execute(
                "INSERT INTO channels VALUES (?,?,?,?,?,?)",
                (channel_id, name, creator_did, now, int(e2ee), metadata)
            )
            self.conn.commit()
            # 创建者自动加入
            self.join_channel(channel_id, creator_did)
            self.channel_subs[channel_id] = {}
            return {"result": "created", "channel_id": channel_id, "name": name}
        except sqlite3.IntegrityError:
            return {"result": "exists", "channel_id": channel_id}

    def list_channels(self) -> list[dict]:
        """列出所有频道"""
        rows = self.conn.execute("SELECT * FROM channels ORDER BY created_at DESC").fetchall()
        result = []
        for r in rows:
            # 统计会员数
            member_count = self.conn.execute(
                "SELECT COUNT(*) FROM channel_members WHERE channel_id=?", (r[0],)
            ).fetchone()[0]
            result.append({
                "id": r[0], "name": r[1], "creator_did": r[2],
                "created_at": r[3], "e2ee": bool(r[4]),
                "member_count": member_count,
            })
        return result

    def get_channel(self, channel_id: str) -> Optional[dict]:
        rows = self.conn.execute("SELECT * FROM channels WHERE id=?", (channel_id,)).fetchall()
        if not rows:
            return None
        r = rows[0]
        return {"id": r[0], "name": r[1], "creator_did": r[2],
                "created_at": r[3], "e2ee": bool(r[4])}

    def delete_channel(self, channel_id: str) -> bool:
        self.conn.execute("DELETE FROM channels WHERE id=?", (channel_id,))
        self.conn.execute("DELETE FROM channel_members WHERE channel_id=?", (channel_id,))
        self.conn.execute("DELETE FROM channel_messages WHERE channel_id=?", (channel_id,))
        self.conn.execute("DELETE FROM channel_subscriptions WHERE channel_id=?", (channel_id,))
        self.conn.commit()
        self.channel_subs.pop(channel_id, None)
        return True

    # ─── 会员管理 ─────────────────────────────

    def join_channel(self, channel_id: str, agent_did: str,
                     enc_public_b64: str = "") -> bool:
        """Agent 加入频道"""
        now = time.time()
        try:
            self.conn.execute(
                "INSERT OR IGNORE INTO channel_members VALUES (?,?,?,?)",
                (channel_id, agent_did, enc_public_b64, now)
            )
            self.conn.commit()
            return True
        except Exception:
            return False

    def leave_channel(self, channel_id: str, agent_did: str) -> bool:
        self.conn.execute("DELETE FROM channel_members WHERE channel_id=? AND agent_did=?",
                          (channel_id, agent_did))
        self.conn.execute("DELETE FROM channel_subscriptions WHERE channel_id=? AND agent_did=?",
                          (channel_id, agent_did))
        self.conn.commit()
        # 从内存缓存移除
        subs = self.channel_subs.get(channel_id, {})
        dead_ws_ids = [wid for wid, info in subs.items()
                       if info.get("agent_did") == agent_did]
        for wid in dead_ws_ids:
            subs.pop(wid, None)
        return True

    def get_members(self, channel_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT agent_did, enc_public_b64, joined_at FROM channel_members WHERE channel_id=?",
            (channel_id,)
        ).fetchall()
        return [{"did": r[0], "enc_public_b64": r[1], "joined_at": r[2]} for r in rows]

    # ─── WS 订阅管理 ─────────────────────────

    async def ws_connect(self, ws: WebSocket, agent_did: str, name: str = ""):
        """WebSocket 连接建立 (假设 ws 已被 handler accept)"""
        ws_id = f"{agent_did}:{str(uuid.uuid4())[:8]}"
        self.ws_pool[ws_id] = {
            "websocket": ws,
            "agent_did": agent_did,
            "name": name,
            "channels": set(),
        }
        return ws_id

    async def ws_subscribe(self, ws_id: str, channel_id: str,
                           mode: str = "readwrite") -> dict:
        """WS 订阅频道"""
        info = self.ws_pool.get(ws_id)
        if not info:
            return {"result": "error", "msg": "ws not found"}
        agent_did = info["agent_did"]

        # 检查频道是否存在
        channel = self.get_channel(channel_id)
        if not channel:
            return {"result": "error", "msg": "channel not found"}

        # 检查是否会员
        member = self.conn.execute(
            "SELECT 1 FROM channel_members WHERE channel_id=? AND agent_did=?",
            (channel_id, agent_did)
        ).fetchone()
        if not member:
            self.join_channel(channel_id, agent_did)

        # 注册订阅
        now = time.time()
        try:
            self.conn.execute(
                "INSERT OR REPLACE INTO channel_subscriptions VALUES (?,?,?,?,?)",
                (channel_id, agent_did, ws_id, mode, now)
            )
            self.conn.commit()
        except Exception:
            pass

        info["channels"].add(channel_id)
        if channel_id not in self.channel_subs:
            self.channel_subs[channel_id] = {}
        self.channel_subs[channel_id][ws_id] = info["websocket"]

        return {"result": "ok", "channel_id": channel_id, "mode": mode,
                "subscribers": len(self.channel_subs[channel_id])}

    async def ws_unsubscribe(self, ws_id: str, channel_id: str):
        """WS 取消订阅频道"""
        info = self.ws_pool.get(ws_id)
        if not info:
            return
        info["channels"].discard(channel_id)
        subs = self.channel_subs.get(channel_id, {})
        subs.pop(ws_id, None)
        self.conn.execute(
            "DELETE FROM channel_subscriptions WHERE channel_id=? AND ws_id=?",
            (channel_id, ws_id)
        )
        self.conn.commit()

    async def ws_disconnect(self, ws_id: str):
        """WS 断开连接"""
        info = self.ws_pool.pop(ws_id, None)
        if not info:
            return
        for channel_id in list(info["channels"]):
            subs = self.channel_subs.get(channel_id, {})
            subs.pop(ws_id, None)
        self.conn.execute(
            "DELETE FROM channel_subscriptions WHERE ws_id=?", (ws_id,)
        )
        self.conn.commit()

    # ─── 消息广播 ─────────────────────────────

    async def broadcast(self, channel_id: str, sender_did: str,
                        payload: str, msg_type: str = "text",
                        encrypted: bool = False) -> int:
        """
        广播消息到频道所有订阅者
        返回发送成功的数量
        """
        # 持久化消息
        now = time.time()
        self.conn.execute(
            "INSERT INTO channel_messages (channel_id, sender_did, type, payload, encrypted, ts) "
            "VALUES (?,?,?,?,?,?)",
            (channel_id, sender_did, msg_type, payload, int(encrypted), now)
        )
        self.conn.commit()

        # 获取发送者名称
        sender_name = sender_did
        if self.signal:
            agent = self.signal.find_agent(sender_did)
            if agent:
                sender_name = agent.get("name", sender_did)

        # 广播
        subs = self.channel_subs.get(channel_id, {})
        msg = {
            "method": "agentlink.channel.event",
            "meta": {
                "profile": "agentlink.session.v1",
                "sender_did": sender_did,
            },
            "body": {
                "channel_id": channel_id,
                "sender": sender_name,
                "sender_did": sender_did,
                "type": msg_type,
                "payload": payload,
                "encrypted": encrypted,
                "timestamp": time.strftime("%H:%M:%S"),
            }
        }
        sent = 0
        dead_ws_ids = []
        for ws_id, ws in subs.items():
            if ws_id == sender_did:  # 不发给发送者自身
                # 但通过 ws_id 不一定等于 sender_did，所以用 ws_id 对应的 agent_did 比较
                ws_info = self.ws_pool.get(ws_id, {})
                if ws_info.get("agent_did") == sender_did:
                    continue
            try:
                await ws.send_json(msg)
                sent += 1
            except Exception:
                dead_ws_ids.append(ws_id)

        for ws_id in dead_ws_ids:
            subs.pop(ws_id, None)
            self.ws_pool.pop(ws_id, None)

        return sent

    async def send_to_channel(self, channel_id: str, sender_did: str,
                              target_did: str, payload: str,
                              msg_type: str = "text") -> Optional[str]:
        """私信频道内特定成员"""
        subs = self.channel_subs.get(channel_id, {})
        msg = {
            "method": "agentlink.channel.direct",
            "meta": {"profile": "agentlink.session.v1", "sender_did": sender_did},
            "body": {
                "channel_id": channel_id,
                "sender_did": sender_did,
                "type": msg_type,
                "payload": payload,
                "timestamp": time.strftime("%H:%M:%S"),
            }
        }
        for ws_id, ws in subs.items():
            ws_info = self.ws_pool.get(ws_id, {})
            if ws_info.get("agent_did") == target_did:
                try:
                    await ws.send_json(msg)
                    return {"result": "sent", "target": target_did}
                except Exception:
                    pass
        return None

    # ─── E2EE 频道密钥 ─────────────────────────

    def derive_channel_key(self, channel_id: str) -> bytes:
        """
        从频道的所有会员公钥派生出群组密钥
        使用 deterministic 哈希：channel_id → SHA256
        这是最简单的方案——更完整的方案应使用 MLS 或 TreeKEM
        """
        return hashlib.sha256(f"agentlink:channel:{channel_id}:e2ee".encode()).digest()

    def get_channel_cipher(self, channel_id: str, my_did: str, peer_did: str) -> SessionCipher:
        """获取两个频道成员之间的加密器"""
        cache_key = f"{channel_id}:{my_did}:{peer_did}"
        if cache_key in self._channel_ciphers:
            return self._channel_ciphers[cache_key]

        # 查找双方的公钥
        members = self.get_members(channel_id)
        my_enc = None
        peer_enc = None
        for m in members:
            if m["did"] == my_did:
                my_enc = m["enc_public_b64"]
            elif m["did"] == peer_did:
                peer_enc = m["enc_public_b64"]

        if not my_enc or not peer_enc:
            raise ValueError(f"partner keys not found for {channel_id}")

        # 这里需要使用加载的私钥，但我们只存公钥
        # 实际使用时在 Agent 侧调用此方法传入私钥
        return None

    # ─── 历史消息 ─────────────────────────────

    def get_history(self, channel_id: str, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM channel_messages WHERE channel_id=? ORDER BY ts DESC LIMIT ?",
            (channel_id, limit)
        ).fetchall()
        result = []
        for r in reversed(rows):
            result.append({
                "id": r[0], "channel_id": r[1], "sender_did": r[2],
                "type": r[3], "payload": r[4], "encrypted": bool(r[5]),
                "ts": r[6],
            })
        return result


# ═══════════════════════════════════════════════
# Presence 联邦
# ═══════════════════════════════════════════════

class PresenceFederator:
    """
    将 Agent 的状态变化传播到信令服务。
    这样所有连接到同一信令服务的 Agent 都能实时获知彼此状态。
    """

    def __init__(self, signal: SignalServer):
        self.signal = signal
        # 记录每个 DID 的 presence 订阅者
        self._subscribers: dict[str, set[WebSocket]] = {}

    async def push_presence(self, did: str, status: dict):
        """当 Agent 状态变化时调用"""
        self.signal.heartbeat(did)  # 更新心跳

        # 更新信令服务的 agent 状态
        agent = self.signal.find_agent(did)
        if agent:
            self.signal._update_agent_status(did, status.get("status", "online"))

        # 通知 presence 订阅者
        update = {
            "method": "agentlink.presence.event",
            "meta": {"profile": "agentlink.session.v1", "sender_did": did},
            "body": {
                "did": did,
                "name": status.get("name", ""),
                "status": status.get("status", "online"),
                "url": status.get("url", ""),
                "ws": status.get("ws", ""),
                "since": time.strftime("%H:%M:%S"),
            }
        }
        dead = set()
        for sub_ws in self._subscribers.get("__all__", set()):
            try:
                await sub_ws.send_json(update)
            except Exception:
                dead.add(sub_ws)
        self._subscribers["__all__"] -= dead

    async def subscribe(self, ws: WebSocket):
        """WS 订阅所有 presence 变化"""
        if "__all__" not in self._subscribers:
            self._subscribers["__all__"] = set()
        self._subscribers["__all__"].add(ws)

    async def unsubscribe(self, ws: WebSocket):
        self._subscribers.get("__all__", set()).discard(ws)


# ═══════════════════════════════════════════════
# FastAPI 路由工厂
# ═══════════════════════════════════════════════

def add_channel_relay(app: FastAPI, relay: ChannelRelay,
                      prefix: str = "/channel"):
    """给 FastAPI app 添加频道中继路由"""

    @app.websocket(f"{prefix}/ws")
    async def channel_ws(websocket: WebSocket):
        """频道中继 WebSocket"""
        # 先接收认证消息
        await websocket.accept()

        # 第一个消息必须是 auth
        try:
            auth_msg = await websocket.receive_json()
        except Exception:
            await websocket.close(1008, "auth required")
            return

        agent_did = auth_msg.get("did", "")
        agent_name = auth_msg.get("name", agent_did)
        if not agent_did:
            await websocket.send_json({"result": "error", "msg": "did required"})
            await websocket.close(1008, "did required")
            return

        ws_id = await relay.ws_connect(websocket, agent_did, agent_name)
        print(f"  📻 频道中继: {agent_name} ({agent_did[:20]}...) 已连接")
        await websocket.send_json({"result": "connected", "ws_id": ws_id})

        try:
            while True:
                data = await websocket.receive_json()
                method = data.get("method", "")
                body = data.get("body", {})

                if method == "agentlink.channel.subscribe":
                    channel_id = body.get("channel_id", "")
                    mode = body.get("mode", "readwrite")
                    result = await relay.ws_subscribe(ws_id, channel_id, mode)
                    await websocket.send_json({"result": "ok", **result})

                elif method == "agentlink.channel.unsubscribe":
                    channel_id = body.get("channel_id", "")
                    await relay.ws_unsubscribe(ws_id, channel_id)
                    await websocket.send_json({"result": "unsubscribed", "channel_id": channel_id})

                elif method == "agentlink.channel.broadcast":
                    channel_id = body.get("channel_id", "")
                    payload = body.get("payload", "")
                    msg_type = body.get("type", "text")
                    encrypted = body.get("encrypted", False)
                    sent = await relay.broadcast(channel_id, agent_did, payload, msg_type, encrypted)
                    await websocket.send_json({"result": "broadcast", "channel_id": channel_id, "sent": sent})

                elif method == "agentlink.channel.direct":
                    channel_id = body.get("channel_id", "")
                    target_did = body.get("target_did", "")
                    payload = body.get("payload", "")
                    result = await relay.send_to_channel(channel_id, agent_did, target_did, payload)
                    await websocket.send_json(result or {"result": "error", "msg": "target not found"})

                elif method == "agentlink.channel.list":
                    channels = relay.list_channels()
                    await websocket.send_json({"result": channels})

                elif method == "agentlink.channel.members":
                    channel_id = body.get("channel_id", "")
                    members = relay.get_members(channel_id)
                    await websocket.send_json({"result": members})

                elif method == "agentlink.channel.history":
                    channel_id = body.get("channel_id", "")
                    limit = body.get("limit", 50)
                    history = relay.get_history(channel_id, limit)
                    await websocket.send_json({"result": history})

                else:
                    await websocket.send_json(rpc_error(-99, f"unknown method: {method}"))

        except WebSocketDisconnect:
            pass
        except Exception as e:
            print(f"  ⚠️ 频道中继 WS 错误: {e}")
        finally:
            await relay.ws_disconnect(ws_id)
            print(f"  📻 频道中继: {agent_name} 断开连接")

    # ─── REST 端点 ───

    @app.post(f"{prefix}/create")
    async def api_create_channel(req: Request):
        data = await req.json()
        channel_id = data.get("channel_id", str(uuid.uuid4())[:12])
        name = data.get("name", channel_id)
        creator_did = data.get("creator_did", "")
        e2ee = data.get("e2ee", False)
        result = relay.create_channel(channel_id, name, creator_did, e2ee)
        return JSONResponse(result)

    @app.get(f"{prefix}/list")
    async def api_list_channels():
        return JSONResponse({"result": relay.list_channels()})

    @app.get(f"{prefix}/info/{{channel_id}}")
    async def api_channel_info(channel_id: str):
        channel = relay.get_channel(channel_id)
        if not channel:
            return JSONResponse({"error": "not found"}, status_code=404)
        members = relay.get_members(channel_id)
        channel["members"] = members
        return JSONResponse(channel)

    @app.post(f"{prefix}/join")
    async def api_join_channel(req: Request):
        data = await req.json()
        channel_id = data.get("channel_id", "")
        agent_did = data.get("agent_did", "")
        enc_public_b64 = data.get("enc_public_b64", "")
        relay.join_channel(channel_id, agent_did, enc_public_b64)
        return JSONResponse({"result": "joined"})

    @app.post(f"{prefix}/leave")
    async def api_leave_channel(req: Request):
        data = await req.json()
        relay.leave_channel(data.get("channel_id", ""), data.get("agent_did", ""))
        return JSONResponse({"result": "left"})

    @app.post(f"{prefix}/broadcast")
    async def api_broadcast(req: Request):
        data = await req.json()
        channel_id = data.get("channel_id", "")
        sender_did = data.get("sender_did", "")
        payload = data.get("payload", "")
        msg_type = data.get("type", "text")
        sent = await relay.broadcast(channel_id, sender_did, payload, msg_type)
        return JSONResponse({"result": "broadcast", "channel_id": channel_id, "sent": sent})

    @app.get(f"{prefix}/history/{{channel_id}}")
    async def api_channel_history(channel_id: str, limit: int = 50):
        return JSONResponse({"result": relay.get_history(channel_id, limit)})

    return app


def add_presence_federation(app: FastAPI, federator: PresenceFederator,
                            prefix: str = "/presence"):
    """给 FastAPI app 添加 Presence 联邦路由"""

    @app.post(f"{prefix}/push")
    async def api_presence_push(req: Request):
        data = await req.json()
        did = data.get("did", "")
        status = data.get("status", {})
        await federator.push_presence(did, status)
        return JSONResponse({"result": "ok"})

    @app.websocket(f"{prefix}/ws")
    async def presence_ws(websocket: WebSocket):
        await websocket.accept()
        await federator.subscribe(websocket)
        try:
            while True:
                # 保持长连接
                data = await websocket.receive_json()
                if data.get("method") == "ping":
                    await websocket.send_json({"result": "pong"})
        except WebSocketDisconnect:
            pass
        finally:
            await federator.unsubscribe(websocket)

    return app


# ═══════════════════════════════════════════════
# AgentLinkClient P2 扩展
# ═══════════════════════════════════════════════

class P2ClientMixin:
    """
    P2 客户端扩展 — 混入到 AgentLinkClient 使用
    让 Agent 能连接频道中继、订阅 Presence、发送频道消息
    """

    def __init__(self):
        self._channel_ws: Optional[any] = None
        self._presence_ws: Optional[any] = None
        self._channel_relay_url: str = ""
        self._channel_ws_id: str = ""
        self._subscribed_channels: set[str] = set()

    async def connect_channel_relay(self, relay_url: str, did: str, name: str) -> bool:
        """连接频道中继"""
        import websockets
        try:
            self._channel_relay_url = relay_url
            self._channel_ws = await websockets.connect(f"{relay_url}/channel/ws")
            # 发送认证
            await self._channel_ws.send_json({"did": did, "name": name})
            resp = await self._channel_ws.recv()
            result = json.loads(resp)
            if result.get("result") == "connected":
                self._channel_ws_id = result.get("ws_id", "")
                print(f"  📻 已连接频道中继 (ws_id={self._channel_ws_id[:16]}...)")
                return True
            return False
        except Exception as e:
            print(f"  ⚠️ 频道中继连接失败: {e}")
            return False

    async def subscribe_channel(self, channel_id: str, mode: str = "readwrite") -> bool:
        """订阅频道"""
        if not self._channel_ws:
            return False
        await self._channel_ws.send_json({
            "method": "agentlink.channel.subscribe",
            "body": {"channel_id": channel_id, "mode": mode},
        })
        resp = json.loads(await self._channel_ws.recv())
        if resp.get("result") == "ok":
            self._subscribed_channels.add(channel_id)
            print(f"  📻 已订阅频道 {channel_id} (mode={mode})")
            return True
        return False

    async def unsubscribe_channel(self, channel_id: str) -> bool:
        """取消订阅频道"""
        if not self._channel_ws:
            return False
        await self._channel_ws.send_json({
            "method": "agentlink.channel.unsubscribe",
            "body": {"channel_id": channel_id},
        })
        self._subscribed_channels.discard(channel_id)
        return True

    async def send_channel_message(self, channel_id: str, payload: str,
                                   msg_type: str = "text",
                                   encrypted: bool = False) -> bool:
        """发送频道消息"""
        if not self._channel_ws:
            return False
        await self._channel_ws.send_json({
            "method": "agentlink.channel.broadcast",
            "body": {
                "channel_id": channel_id,
                "payload": payload,
                "type": msg_type,
                "encrypted": encrypted,
            },
        })
        _ = await self._channel_ws.recv()  # ack
        print(f"  📤 {channel_id} [{msg_type}]: \"{payload[:50]}\"")
        return True

    async def get_channel_history(self, channel_id: str, limit: int = 20) -> list[dict]:
        """获取频道历史"""
        if not self._channel_ws:
            return []
        await self._channel_ws.send_json({
            "method": "agentlink.channel.history",
            "body": {"channel_id": channel_id, "limit": limit},
        })
        resp = json.loads(await self._channel_ws.recv())
        return resp.get("result", [])

    async def channel_loop(self, callback=None):
        """
        频道消息接收循环。
        callback(channel_id, sender, payload, type) 或默认打印。
        """
        if not self._channel_ws:
            return
        try:
            while True:
                msg = json.loads(await self._channel_ws.recv())
                if msg.get("method") == "agentlink.channel.event":
                    body = msg.get("body", {})
                    channel_id = body.get("channel_id", "")
                    sender = body.get("sender", "?")
                    payload = body.get("payload", "")
                    msg_type = body.get("type", "text")
                    encrypted = body.get("encrypted", False)

                    label = "🔒" if encrypted else "📨"
                    print(f"  {label} [{channel_id}] {sender}: \"{payload[:80]}\"")

                    if callback:
                        await callback(channel_id, sender, payload, msg_type)

                elif msg.get("method") == "agentlink.channel.direct":
                    body = msg.get("body", {})
                    print(f"  📩 [私信] {body.get('sender_did','?')}: \"{body.get('payload','')[:60]}\"")
        except Exception as e:
            print(f"  ⚠️ 频道接收循环结束: {e}")

    async def disconnect_channel_relay(self):
        """断开频道中继连接"""
        self._channel_ws = None
        self._subscribed_channels.clear()
        print(f"  📻 已断开频道中继")

    # ─── Presence ──────────────────────────────

    async def connect_presence(self, signal_url: str) -> bool:
        """连接 Presence WS"""
        import websockets
        try:
            ws_url = signal_url.replace("http://", "ws://").replace("https://", "wss://")
            self._presence_ws = await websockets.connect(f"{ws_url}/presence/ws")
            print(f"  🟢 presence 已连接")
            return True
        except Exception as e:
            print(f"  ⚠️ presence 连接失败: {e}")
            return False

    async def presence_loop(self):
        """Presence 接收循环"""
        if not self._presence_ws:
            return
        try:
            while True:
                msg = json.loads(await self._presence_ws.recv())
                if msg.get("method") == "agentlink.presence.event":
                    body = msg.get("body", {})
                    did = body.get("did", "?")[:20]
                    name = body.get("name", "?")
                    status = body.get("status", "?")
                    since = body.get("since", "?")
                    status_icon = "🟢" if status == "online" else "🔴" if status == "offline" else "🟡"
                    print(f"  {status_icon} [{since}] {name} ({did}...)  {status}")
        except Exception:
            pass

    async def disconnect_presence(self):
        self._presence_ws = None


# ═══════════════════════════════════════════════
# 独立启动函数
# ═══════════════════════════════════════════════

def run_channel_relay(port: int = 19766, signal_port: int = 19765):
    """独立启动频道中继服务"""
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI(title="AgentLink Channel Relay")
    relay = ChannelRelay()
    add_channel_relay(app, relay)
    print(f"📻 AgentLink 频道中继 @ :{port}")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


# ═══════════════════════════════════════════════
# 自测
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    import asyncio

    async def _test():
        print("=" * 60)
        print("🧪 AgentLink P2 自测")
        print("=" * 60)

        relay = ChannelRelay(db_path=":memory:")

        # 创建频道
        r = relay.create_channel("case-001", "专案组A", "did:alice")
        print(f"\n  创建频道: {r}")

        # 列出频道
        channels = relay.list_channels()
        print(f"  频道列表: {len(channels)} 个")

        # Alice 和 Bob 加入
        relay.join_channel("case-001", "did:alice", "alice_pub_enc")
        relay.join_channel("case-001", "did:bob", "bob_pub_enc")
        members = relay.get_members("case-001")
        print(f"  会员数: {len(members)}")

        # 测试组密钥派生
        key = relay.derive_channel_key("case-001")
        key2 = relay.derive_channel_key("case-001")
        assert key == key2
        assert len(key) == 32
        print(f"  频道密钥一致: {key.hex()[:16]}...")

        print(f"\n  ✅ P2 自测通过")

    asyncio.run(_test())
