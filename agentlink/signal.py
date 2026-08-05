"""
AgentLink Signaling Server — 轻量信令服务
功能：注册/发现/在线状态/离线缓存
依赖：pip install fastapi uvicorn cryptography
"""
from __future__ import annotations
import asyncio, json, os, sqlite3, time, uuid
from dataclasses import dataclass, field
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# 导入加密模块
import sys, os as _os
sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from .crypto import (
    verify_did_binding, SessionCipher,
    compute_shared_secret, derive_session_key,
    encrypt_message, decrypt_message,
    generate_keypair, save_keypair, load_keypair,
    _b64, _unb64,
)


# ─── 配置 ─────────────────────────────────────

DEFAULT_PORT = 9765
DB_PATH = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "agentlink_signal.db")
KEY_PATH = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "signal_key.json")

OFFLINE_EXPIRE_SEC = 3600 * 24 * 7  # 离线消息保留 7 天
HEARTBEAT_TIMEOUT = 60               # 60 秒无心跳 = 离线


# ─── 数据库 ─────────────────────────────────────

def init_db(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            did TEXT PRIMARY KEY,
            name TEXT,
            http_url TEXT,
            ws_url TEXT,
            sign_public_b64 TEXT,
            enc_public_b64 TEXT,
            status TEXT DEFAULT 'offline',
            last_seen REAL DEFAULT 0,
            registered_at REAL DEFAULT 0,
            metadata TEXT DEFAULT '{}'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS offline_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_did TEXT,
            sender_did TEXT,
            message_type TEXT DEFAULT 'text',
            payload TEXT,
            encrypted_b64 TEXT,
            created_at REAL DEFAULT 0,
            delivered_at REAL DEFAULT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS public_channels (
            channel_id TEXT PRIMARY KEY,
            name TEXT,
            creator_did TEXT,
            created_at REAL DEFAULT 0,
            metadata TEXT DEFAULT '{}'
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_offline_target ON offline_messages(target_did)
    """)
    conn.commit()
    conn.close()


# ─── 信令服务核心 ───────────────────────────────

class SignalServer:
    """轻量信令服务"""

    def __init__(self, db_path: str = DB_PATH, key_path: str = KEY_PATH):
        self.db_path = db_path
        self.key_path = key_path
        self.ws_connections: dict[str, WebSocket] = {}  # did -> ws

        # 生成或加载服务端密钥对
        if os.path.exists(key_path):
            self.kp = load_keypair(key_path)
            print(f"🔑 加载服务端密钥: {self.kp.did}")
        else:
            self.kp = generate_keypair("signal")
            save_keypair(self.kp, key_path)
            print(f"🔑 生成服务端密钥: {self.kp.did}")

        init_db(db_path)

    # ─── DB helpers ───

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def register_agent(self, did: str, name: str,
                       http_url: str, ws_url: str,
                       sign_public_b64: str, enc_public_b64: str,
                       metadata: dict = None) -> bool:
        """注册一个 agent"""
        now = time.time()
        conn = self._conn()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO agents
                (did, name, http_url, ws_url, sign_public_b64, enc_public_b64,
                 status, last_seen, registered_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, 'online', ?, ?, ?)
            """, (did, name, http_url, ws_url,
                  sign_public_b64, enc_public_b64,
                  now, now if not metadata else now,
                  json.dumps(metadata or {})))
            conn.commit()
            return True
        finally:
            conn.close()

    def unregister_agent(self, did: str):
        conn = self._conn()
        try:
            conn.execute("UPDATE agents SET status='offline', last_seen=? WHERE did=?", (time.time(), did))
            conn.commit()
        finally:
            conn.close()

    def find_agent(self, did: str) -> Optional[dict]:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT did, name, http_url, ws_url, sign_public_b64, enc_public_b64, "
                "status, last_seen, metadata FROM agents WHERE did=?"
            , (did,)).fetchone()
            if row:
                return {
                    "did": row[0], "name": row[1], "http_url": row[2],
                    "ws_url": row[3], "sign_public_b64": row[4],
                    "enc_public_b64": row[5], "status": row[6],
                    "last_seen": row[7], "metadata": json.loads(row[8] or "{}"),
                }
            return None
        finally:
            conn.close()

    def list_online(self) -> list[dict]:
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT did, name, http_url, ws_url, sign_public_b64, enc_public_b64, "
                "status, last_seen, metadata FROM agents WHERE status='online' "
                "ORDER BY last_seen DESC"
            ).fetchall()
            return [{
                "did": r[0], "name": r[1], "http_url": r[2],
                "ws_url": r[3], "sign_public_b64": r[4],
                "enc_public_b64": r[5], "status": r[6],
                "last_seen": r[7], "metadata": json.loads(r[8] or "{}"),
            } for r in rows]
        finally:
            conn.close()

    def heartbeat(self, did: str) -> bool:
        conn = self._conn()
        try:
            now = time.time()
            conn.execute("UPDATE agents SET last_seen=?, status='online' WHERE did=?", (now, did))
            conn.commit()
            return conn.total_changes > 0
        finally:
            conn.close()

    # ─── 离线消息 ───

    def store_offline_msg(self, target_did: str, sender_did: str,
                          message_type: str, payload: str = "",
                          encrypted_b64: str = "") -> int:
        conn = self._conn()
        try:
            now = time.time()
            cursor = conn.execute("""
                INSERT INTO offline_messages
                (target_did, sender_did, message_type, payload, encrypted_b64, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (target_did, sender_did, message_type, payload, encrypted_b64, now))
            conn.commit()
            return cursor.lastrowid or 0
        finally:
            conn.close()

    def get_offline_msgs(self, target_did: str, mark_delivered: bool = True) -> list[dict]:
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT id, sender_did, message_type, payload, encrypted_b64, created_at "
                "FROM offline_messages WHERE target_did=? AND delivered_at IS NULL "
                "ORDER BY created_at ASC"
            , (target_did,)).fetchall()
            msgs = [{
                "id": r[0], "sender_did": r[1], "type": r[2],
                "payload": r[3], "encrypted_b64": r[4], "created_at": r[5],
            } for r in rows]
            if mark_delivered and msgs:
                ids = tuple(m["id"] for m in msgs)
                conn.execute(
                    f"UPDATE offline_messages SET delivered_at=? WHERE id IN ({','.join('?'*len(ids))})",
                    (time.time(), *ids)
                )
                conn.commit()
            return msgs
        finally:
            conn.close()

    def get_agent_enc_key(self, did: str) -> Optional[str]:
        """获取 agent 的加密公钥（用于端到端加密离线消息）"""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT enc_public_b64 FROM agents WHERE did=?"
            , (did,)).fetchone()
            return row[0] if row else None
        finally:
            conn.close()


# ─── 创建 FastAPI app ──────────────────────────

# 此函数会在路由创建后被调用
# 先声明占位

def create_signal_app(signal: SignalServer) -> FastAPI:

    app = FastAPI(title="AgentLink Signal Server")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:*", "http://127.0.0.1:*"],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
    )

    # ─── REST API ───

    @app.post("/signal/register")
    async def api_register(req: Request):
        """agent 注册 — 验证 DID 绑定凭证 + enc_public 一致性"""
        data = await req.json()
        did: str = data.get("did", "")
        cert: dict = data.get("cert", {})
        enc_b64: str = data.get("enc_public_b64", "")

        # 验证 DID 绑定凭证（签名有效性）
        if cert:
            if not verify_did_binding(cert):
                return {"error": "DID 绑定凭证验证失败"}
            if cert.get("did") != did:
                return {"error": "DID 不匹配"}
            # 额外验证：cert 中的 enc_public 与注册的 enc_public 一致
            cert_enc = cert.get("enc_public_b64", "")
            if enc_b64 and cert_enc and enc_b64 != cert_enc:
                return {"error": "enc_public_b64 与凭证不符"}

        # DID 首次注册绑定：若 DID 已存在，验证 enc_public 一致（防冒充）
        existing = signal.find_agent(did)
        if existing:
            existing_enc = existing.get("enc_public_b64", "")
            if enc_b64 and existing_enc and enc_b64 != existing_enc:
                return {"error": "DID 已绑定不同密钥，身份冒充被拒绝"}

        ok = signal.register_agent(
            did=did,
            name=data.get("name", did),
            http_url=data.get("http_url", ""),
            ws_url=data.get("ws_url", ""),
            sign_public_b64=data.get("sign_public_b64", ""),
            enc_public_b64=enc_b64,
            metadata=data.get("metadata"),
        )
        return {"result": "ok" if ok else "error"}

    @app.post("/signal/unregister")
    async def api_unregister(req: Request):
        data = await req.json()
        signal.unregister_agent(data.get("did", ""))
        if data.get("did", "") in signal.ws_connections:
            ws = signal.ws_connections.pop(data["did"], None)
            if ws:
                try:
                    await ws.close()
                except:
                    pass
        return {"result": "ok"}

    @app.post("/signal/heartbeat")
    async def api_heartbeat(req: Request):
        data = await req.json()
        signal.heartbeat(data.get("did", ""))
        return {"result": "ok"}

    @app.get("/signal/find/{did}")
    async def api_find(did: str):
        """根据 DID 查找 agent"""
        agent = signal.find_agent(did)
        if not agent:
            return {"error": "not_found"}
        # 不返回敏感信息
        return {
            "did": agent["did"],
            "name": agent["name"],
            "http_url": agent["http_url"],
            "ws_url": agent["ws_url"],
            "sign_public_b64": agent["sign_public_b64"],
            "enc_public_b64": agent["enc_public_b64"],
            "status": agent["status"],
            "last_seen": agent["last_seen"],
        }

    @app.get("/signal/online")
    async def api_online():
        """列出所有在线 agent"""
        agents = signal.list_online()
        return {
            "count": len(agents),
            "agents": [{
                "did": a["did"], "name": a["name"],
                "status": a["status"], "last_seen": a["last_seen"],
            } for a in agents],
        }

    @app.post("/signal/offline_msg")
    async def api_offline_msg(req: Request):
        """存储离线消息"""
        data = await req.json()
        mid = signal.store_offline_msg(
            target_did=data.get("target_did", ""),
            sender_did=data.get("sender_did", ""),
            message_type=data.get("type", "text"),
            payload=data.get("payload", ""),
            encrypted_b64=data.get("encrypted_b64", ""),
        )
        return {"message_id": mid}

    @app.get("/signal/offline_msg/{did}")
    async def api_get_offline(did: str, req: Request):
        """获取离线消息 — 需 Authorization header 携带 DID 签名"""
        # 鉴权：检查请求是否带有效 DID 签名 token
        auth = req.headers.get("Authorization", "")
        if not auth or not auth.startswith("Bearer "):
            return {"error": "未授权：需要 Authorization: Bearer <token>"}
        # 简单校验：token 中包含目标 DID 才允许拉取
        # 完整方案应使用 DID 签名挑战
        token_did = auth[7:] if len(auth) > 7 else ""
        if token_did != did:
            return {"error": "无权拉取其他 DID 的离线消息"}
        msgs = signal.get_offline_msgs(did)
        return {"count": len(msgs), "messages": msgs}

    @app.get("/signal/status")
    async def api_status():
        """服务状态"""
        online = signal.list_online()
        return {
            "server_did": signal.kp.did,
            "online_agents": len(online),
            "agents": [a["name"] for a in online],
        }

    # ─── WebSocket ───

    @app.websocket("/signal/ws")
    async def ws_handler(ws: WebSocket):
        await ws.accept()
        agent_did = None

        try:
            while True:
                data = await ws.receive_json()
                method = data.get("method", "")
                body = data.get("params", {})

                if method == "signal.auth":
                    # 身份认证
                    agent_did = body.get("did", "")
                    cert = body.get("cert", {})

                    if cert and not verify_did_binding(cert):
                        await ws.send_json({"error": "DID 凭证验证失败"})
                        continue

                    signal.register_agent(
                        did=agent_did,
                        name=body.get("name", agent_did),
                        http_url=body.get("http_url", ""),
                        ws_url="",  # WS 连接已建立
                        sign_public_b64=body.get("sign_public_b64", ""),
                        enc_public_b64=body.get("enc_public_b64", ""),
                    )
                    signal.ws_connections[agent_did] = ws

                    # 推送离线消息
                    offline = signal.get_offline_msgs(agent_did)
                    if offline:
                        await ws.send_json({
                            "method": "signal.offline_messages",
                            "params": {"messages": offline},
                        })

                    await ws.send_json({
                        "result": "authenticated",
                        "params": {"server_did": signal.kp.did},
                    })

                elif method == "signal.heartbeat":
                    if agent_did:
                        signal.heartbeat(agent_did)
                    await ws.send_json({"result": "pong"})

                elif method == "signal.relay":
                    """转发消息到另一个 agent"""
                    target_did = body.get("target_did", "")
                    payload = body.get("payload", {})

                    target_ws = signal.ws_connections.get(target_did)
                    if target_ws:
                        try:
                            await target_ws.send_json({
                                "method": "signal.incoming",
                                "params": {
                                    "from_did": agent_did,
                                    "payload": payload,
                                }
                            })
                            await ws.send_json({
                                "result": "relayed",
                                "params": {"target_did": target_did},
                            })
                        except Exception:
                            # 对方断线
                            signal.unregister_agent(target_did)
                            signal.ws_connections.pop(target_did, None)
                            # 存离线
                            signal.store_offline_msg(
                                target_did, agent_did or "unknown",
                                "relay", json.dumps(payload),
                            )
                            await ws.send_json({
                                "result": "offlined",
                                "params": {"target_did": target_did},
                            })
                    else:
                        # 对方离线，存缓存
                        signal.store_offline_msg(
                            target_did, agent_did or "unknown",
                            "relay", json.dumps(payload),
                        )
                        await ws.send_json({
                            "result": "offlined",
                            "params": {"target_did": target_did},
                        })

                elif method == "signal.find":
                    target_did = body.get("did", "")
                    agent_info = signal.find_agent(target_did)
                    if agent_info:
                        await ws.send_json({
                            "result": "found",
                            "params": {
                                "did": agent_info["did"],
                                "name": agent_info["name"],
                                "http_url": agent_info["http_url"],
                                "ws_url": agent_info["ws_url"],
                                "status": agent_info["status"],
                            }
                        })
                    else:
                        await ws.send_json({
                            "error": "not_found",
                            "params": {"did": target_did},
                        })

                elif method == "signal.online_list":
                    agents = signal.list_online()
                    await ws.send_json({
                        "result": "ok",
                        "params": {"count": len(agents), "agents": [
                            {"did": a["did"], "name": a["name"],
                             "status": a["status"]} for a in agents
                        ]},
                    })

                else:
                    await ws.send_json({"error": f"unknown method: {method}"})

        except WebSocketDisconnect:
            if agent_did:
                signal.ws_connections.pop(agent_did, None)
                signal.unregister_agent(agent_did)
        except Exception as e:
            if agent_did:
                signal.ws_connections.pop(agent_did, None)

    return app


# ─── 启动 ─────────────────────────────────────

def run_signal(port: int = DEFAULT_PORT, host: str = "0.0.0.0"):
    signal = SignalServer()
    app = create_signal_app(signal)
    print(f"\n📡 AgentLink 信令服务启动 @ {host}:{port}")
    print(f"   服务端 DID: {signal.kp.did}")
    print(f"   数据库: {signal.db_path}")
    print(f"   REST:     http://{host}:{port}/signal/status")
    print(f"   WebSocket: ws://{host}:{port}/signal/ws")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run_signal()
