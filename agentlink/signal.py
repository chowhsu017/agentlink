"""
AgentLink Signaling Server — 轻量信令服务
功能：注册/发现/在线状态/离线缓存
依赖：pip install fastapi uvicorn cryptography
"""
from __future__ import annotations
import asyncio, hashlib, json, os, sqlite3, time, uuid
from dataclasses import dataclass, field
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .logbook import log
import uvicorn

# 导入加密模块
import sys, os as _os
sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from .crypto import (
    verify_did_binding, SessionCipher,
    compute_shared_secret, derive_session_key,
    encrypt_message, decrypt_message,
    generate_keypair, save_keypair, load_keypair,
    verify_message,
    _b64, _unb64,
)


# ─── 配置 ─────────────────────────────────────

DEFAULT_PORT = 9765
DB_PATH = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "agentlink_signal.db")
KEY_PATH = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "signal_key.json")

OFFLINE_EXPIRE_SEC = 3600 * 24 * 7  # 离线消息保留 7 天
HEARTBEAT_TIMEOUT = 60               # 60 秒无心跳 = 离线

# P0-4：DID 签名 Bearer token 的有效期（秒）与时钟容差
auth_TOKEN_TTL = 120
auth_CLOCK_SKEW = 30


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
        CREATE TABLE IF NOT EXISTS comm_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            kind TEXT NOT NULL,
            sender_did TEXT NOT NULL,
            target_did TEXT,
            channel_id TEXT,
            payload_len INTEGER DEFAULT 0,
            msg_hash TEXT,
            delivered INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON comm_audit(ts)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_audit_pair ON comm_audit(sender_did, target_did)
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
        # P1-4/P1-5：挑战 nonce（HTTP 用 did 作键；WS 用 "__ws__{id(ws)}" 作键）
        self._challenges: dict[str, dict] = {}
        self._consumed_challenge_ws: dict[int, str] = {}

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
        # P1-2：SQLite 连接不再跨线程/协程共享。
        #   · check_same_thread=False + 每调用新建连接 → 避免「database is locked」
        #   · timeout=5 → 突发并发下排队而非立即抛错
        #   · WAL 模式 → 读写并行，减少锁竞争
        conn = sqlite3.connect(self.db_path, timeout=5.0, check_same_thread=False)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
        except Exception as e:  # noqa: BLE001
            log.debug("db", "设置 WAL/busy_timeout 失败（环境不支持则忽略）", exc=e)
        return conn

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

    # ─── P0-4：DID 签名 bear token（挑战-响应式）───

    def issue_challenge(self, did: str) -> str:
        """为指定 DID 下发一次性挑战 nonce。"""
        nonce = uuid.uuid4().hex + uuid.uuid4().hex[:8]
        if not hasattr(self, "_challenges"):
            self._challenges = {}
        self._challenges[did] = {"nonce": nonce, "ts": time.time()}
        return nonce

    def verify_token(self, token: str) -> Optional[str]:
        """
        验证 `Authorization: Bearer <token>` 的签名，返回 DID 或 None。

        token 格式：base64url(json).base64url(sig_hex_ascii)
          json = {"did":..., "ts":..., "nonce":...}
          sig  = Ed25519 签名（对 `agentlink-auth-v1:` + json 字节）
        验签公钥从已注册 agent 的 sign_public_b64 取。
        """
        try:
            from .crypto import _unb64
            body_b64, _, sig_b64 = token.partition(".")
            if not body_b64 or not sig_b64:
                return None
            body = _unb64(body_b64)
            sig = _unb64(sig_b64)
            data = json.loads(body.decode("utf-8"))
            did = data.get("did", "")
            ts = float(data.get("ts", 0))
            nonce = data.get("nonce", "")
            if not did:
                return None
            now = time.time()
            # 时效：ts 必须在 [now-TTL-skew, now+skew] 内
            if abs(now - ts) > (auth_TOKEN_TTL + auth_CLOCK_SKEW):
                return None
            # 一次性 nonce：必须由本服务签发且未过期
            ch = getattr(self, "_challenges", {}).get(did)
            if not ch or ch.get("nonce") != nonce:
                return None
            # 取注册公钥验签
            agent = self.find_agent(did)
            if not agent or not agent.get("sign_public_b64"):
                return None
            pub = _unb64(agent["sign_public_b64"])
            if not verify_message(pub, b"agentlink-auth-v1:" + body, sig):
                return None
            # 用掉 nonce（防重放）
            self._challenges.pop(did, None)
            return did
        except Exception as e:  # noqa: BLE001
            log.warn("auth", "token 验证异常（视为无效）", exc=e)
            return None

    def _require_admin(self, req: Request) -> bool:
        """P0-5：审计类接口的访问控制。
        优先：请求来自本机（127.0.0.1）→ 放行；
        否则：需 env AGENTLINK_ADMIN_TOKEN 且 header 匹配。
        """
        try:
            client = getattr(req, "client", None)
            if client is not None and getattr(client, "host", "") in ("127.0.0.1", "::1", "localhost"):
                return True
        except Exception as e:  # noqa: BLE001
            log.debug("auth", "读取 client.host 失败，按非本机处理", exc=e)
        import os as _os
        want = _os.environ.get("AGENTLINK_ADMIN_TOKEN", "")
        got = req.headers.get("X-Admin-Token", "") if req else ""
        return bool(want) and got == want

    # ─── 通信审计（反合谋可审计性）───

    def audit_comm(self, kind: str, sender_did: str,
                   target_did: Optional[str] = None,
                   channel_id: Optional[str] = None,
                   payload=None, delivered: bool = False) -> None:
        """记录一次通信事件。只追加，不更新。

        设计原则：
        - 只存 payload_len 与 msg_hash，**不存明文**（保持 E2EE 语义）
        - 哈希用于事后验证「这条消息内容有没有被改动」
        - 写入在服务端，agent 进程无法篡改
        """
        if payload is None:
            blob = b""
        elif isinstance(payload, (bytes, bytearray)):
            blob = bytes(payload)
        else:
            try:
                blob = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            except Exception:
                blob = str(payload).encode("utf-8", "ignore")

        msg_hash = hashlib.sha256(blob).hexdigest()[:32] if blob else None

        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO comm_audit "
                "(ts, kind, sender_did, target_did, channel_id, payload_len, msg_hash, delivered) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (time.time(), kind, sender_did, target_did, channel_id,
                 len(blob), msg_hash, 1 if delivered else 0),
            )
            conn.commit()
        except Exception as e:  # noqa: BLE001
            log.warn("audit", "审计写入失败（不影响主链路）", exc=e, kind=kind)
        finally:
            conn.close()

    def audit_recent(self, hours: float = 24.0) -> list[dict]:
        conn = self._conn()
        try:
            since = time.time() - hours * 3600
            rows = conn.execute(
                "SELECT ts, kind, sender_did, target_did, channel_id, payload_len, delivered "
                "FROM comm_audit WHERE ts >= ? ORDER BY ts DESC", (since,)
            ).fetchall()
            return [{
                "ts": r[0], "kind": r[1], "sender": r[2],
                "target": r[3], "channel": r[4],
                "payload_len": r[5], "delivered": bool(r[6]),
            } for r in rows]
        finally:
            conn.close()

    def audit_pair_counts(self, hours: float = 24.0) -> list[dict]:
        """点对点通信计数（用于发现非预期配对）"""
        conn = self._conn()
        try:
            since = time.time() - hours * 3600
            rows = conn.execute(
                "SELECT sender_did, target_did, COUNT(*) AS n "
                "FROM comm_audit "
                "WHERE ts >= ? AND kind = 'relay' AND target_did IS NOT NULL "
                "GROUP BY sender_did, target_did ORDER BY n DESC", (since,)
            ).fetchall()
            return [{"sender": r[0], "target": r[1], "count": r[2]} for r in rows]
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
        """agent 注册 — 验证 DID 绑定凭证（P1-5：含时效）+ enc_public 一致性"""
        data = await req.json()
        did: str = data.get("did", "")
        cert: dict = data.get("cert", {})
        enc_b64: str = data.get("enc_public_b64", "")

        # 验证 DID 绑定凭证（签名有效性 + P1-5 时效）
        if cert:
            if not verify_did_binding(cert):
                return {"error": "DID 绑定凭证验证失败（签名/指纹/时效）"}
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

    @app.post("/signal/auth/challenge")
    async def api_auth_challenge(req: Request):
        """P0-4：为指定 DID 下发一次性挑战 nonce（获取签名 token 的第一步）。"""
        data = await req.json()
        did = data.get("did", "")
        if not did:
            return {"error": "did required"}
        return {"did": did, "nonce": signal.issue_challenge(did)}

    @app.get("/signal/offline_msg/{did}")
    async def api_get_offline(did: str, req: Request):
        """获取离线消息 — P0-4：必须携带 **Ed25519 签名**的 Bearer token。

        鉴权流程：
          ① 客户端 POST /signal/auth/challenge {did} → 拿 nonce
          ② 客户端构造 body={"did","ts","nonce"}，用私钥签 `agentlink-auth-v1:`+body
          ③ Authorization: Bearer b64(body).b64(sig)
          ④ 本接口验签 + 校验时效/一次性 nonce，且 token 内的 did 必须 == 路径 did
        （旧版「token 就是 DID 字符串」的伪鉴权已废除）
        """
        auth = req.headers.get("Authorization", "")
        if not auth or not auth.startswith("Bearer "):
            return {"error": "未授权：需要 Authorization: Bearer <signed token>"}
        token = auth[7:].strip()
        token_did = signal.verify_token(token)
        if not token_did:
            return {"error": "未授权：token 签名无效/过期/已使用"}
        if token_did != did:
            return {"error": "无权拉取其他 DID 的离线消息"}
        msgs = signal.get_offline_msgs(did)
        return {"count": len(msgs), "messages": msgs}

    @app.get("/signal/audit")
    async def api_audit(req: Request, hours: float = 24.0):
        """通信审计：最近 N 小时的通信记录 + 点对点计数 + 合谋信号

        P0-5：本接口暴露全站通信元数据（社交图谱/合谋分析），**必须鉴权**：
          · 本机请求（127.0.0.1）放行
          · 非本机需 header `X-Admin-Token` == env `AGENTLINK_ADMIN_TOKEN`

        注意：返回的是**元数据**（谁和谁、多少条、内容哈希），不含明文。
        """
        if not signal._require_admin(req):
            return JSONResponse({"error": "未授权：审计接口仅限本机或管理员"},
                                status_code=403)
        recent = signal.audit_recent(hours=hours)
        pairs = signal.audit_pair_counts(hours=hours)

        # ── 合谋信号：非预期配对 ──
        # 判据：某对 agent 的通信量显著高于同批次的均值
        anomalies = []
        if pairs:
            counts = [p_["count"] for p_ in pairs]
            avg = sum(counts) / len(counts)
            for p_ in pairs:
                if avg > 0 and p_["count"] >= max(3, avg * 3):
                    anomalies.append({
                        "sender": p_["sender"], "target": p_["target"],
                        "count": p_["count"],
                        "ratio_vs_avg": round(p_["count"] / avg, 2),
                        "note": "非预期配对：通信量显著高于均值",
                    })

        return {
            "window_hours": hours,
            "total_events": len(recent),
            "pair_count": len(pairs),
            "anomalies": anomalies,
            "pairs_top": pairs[:20],
            "recent": recent[:100],
        }

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
        # P1-5：连接建立后先下发一次性挑战 nonce（客户端证明持有 DID 私钥）
        ws_challenge = signal.issue_challenge(f"__ws__{id(ws)}")
        signal._consumed_challenge_ws[id(ws)] = ws_challenge
        try:
            await ws.send_json({
                "method": "signal.challenge",
                "params": {"nonce": ws_challenge,
                           "note": "请在 signal.auth 的 cert.nonce 中回传此值"},
            })
        except Exception as e:  # noqa: BLE001
            log.warn("auth", "下发 WS 挑战 nonce 失败", exc=e)

        try:
            while True:
                data = await ws.receive_json()
                method = data.get("method", "")
                body = data.get("params", {})

                if method == "signal.auth":
                    # 身份认证
                    agent_did = body.get("did", "")
                    cert = body.get("cert", {})

                    # P1-5：验证签名/指纹/时效；如果本次 WS 下过 challenge，还须匹配 nonce
                    exp_nonce = signal._consumed_challenge_ws.get(id(ws), "")
                    if cert and not verify_did_binding(cert, expected_nonce=exp_nonce):
                        await ws.send_json({"error": "DID 凭证验证失败（签名/时效/挑战不匹配）"})
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
                            # ── 审计：转发成功 ──
                            signal.audit_comm(
                                kind="relay",
                                sender_did=agent_did or "unknown",
                                target_did=target_did,
                                payload=payload,
                                delivered=True,
                            )
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
                            signal.audit_comm(
                                kind="offline",
                                sender_did=agent_did or "unknown",
                                target_did=target_did,
                                payload=payload,
                                delivered=False,
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
                        signal.audit_comm(
                            kind="offline",
                            sender_did=agent_did or "unknown",
                            target_did=target_did,
                            payload=payload,
                            delivered=False,
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
