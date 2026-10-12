"""
AgentLink Secure Session — 加密会话集成层
将 agentlink_crypto 集成到 agentlink_p1.py 的回调体系中

工作流：
  呼叫方 → 附带 enc_public + sign_public 到 call_req
  响应方 → 用对方公钥 DH + HKDF → SessionCipher
  响应方 → 在自己的 accept 回复中附带自己的公钥
  呼叫方 → 用对方公钥 DH + HKDF → 相同 SessionCipher
  数据帧自动加解密 → 对应用层透明
"""
from __future__ import annotations
import json, base64
from typing import Optional, Callable, Awaitable

# 同一目录
from .crypto import (
    AgentKeyPair, SessionCipher, generate_keypair, load_keypair, save_keypair,
    compute_shared_secret, derive_session_key,
    encrypt_message, decrypt_message,
    sign_message, verify_message,
    sign_did_binding, verify_did_binding,
    _b64, _unb64,
)
from .logbook import log


def _maybe_decode(s: str) -> bytes:
    """base64 解码如果字符串是 base64，否则直接取 UTF-8 bytes"""
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return s.encode()


# ═══════════════════════════════════════════════
# 加密会话管理器
# ═══════════════════════════════════════════════

class SecureSessionManager:
    """
    管理一个 AgentLinkState 的加密上下文。
    通过 attach_to_state() 注入 P1 的回调系统。
    """

    def __init__(self, state, keypair: Optional[AgentKeyPair] = None):
        """
        state: AgentLinkState 实例
        keypair: 若为 None 则自动生成
        """
        self.state = state
        self.kp = keypair or generate_keypair(state.name)
        self.cipher: Optional[SessionCipher] = None
        self.peer_cipher: Optional[SessionCipher] = None  # 对方视角的 cipher（两侧对称）
        self.e2ee_enabled = False
        self.peer_did_binding: Optional[dict] = None
        self._ring_hook = None
        self._accept_hook = None
        self._data_hook = None
        self._node_ref = None       # 绑定的 AgentLinkNode（账本同步用）
        # ── v0.2 会话账本 ──────────────────────────────
        self.ledger = None          # SessionLedger；会话建立时创建
        self._frame_seq_in = 0      # 已记录入站帧数
        self._frame_seq_out = 0     # 已记录出站帧数
        self._is_initiator = True   # v0.3 C1：本端角色（sig_object 定序用）

    # ─── 公钥导出 ───

    def get_public_payload(self) -> dict:
        """用于附带在 call_req / call_accept 消息中的公钥信息"""
        return {
            "enc_public_b64": _b64(self.kp.enc_public),
            "sign_public_b64": _b64(self.kp.sign_public),
            "did": self.kp.did,
        }

    def get_auth_payload(self, nonce: str = "") -> dict:
        """附带 DID 绑定凭证。

        P1-5：cert **每次调用现签**（timestamp=当前），否则启动超过时效窗口（300s）后
        重连/注册会因凭证过期而认证失败。若服务端下发了挑战 nonce，应传入 nonce 一并签名。
        """
        return {
            **self.get_public_payload(),
            "cert": sign_did_binding(self.kp, nonce=nonce),
        }

    # ─── 密钥协商 —— 发起方 ───

    def _peer_from_ctx(self) -> tuple:
        """从 context 提取对端公钥和 DID，兼容不同 key 名"""
        _ctx = getattr(self.state, '_call_context', {})
        # 不变量断言 #1：call_context 必须在加密前已 set
        # （否则一直拿空 dict → 明文降级且不报错 → AgentLink 曾踩的静默降级坑）
        if self.e2ee_enabled or self.cipher is not None:
            assert _ctx, "call_context must be set before encrypt"
        enc_b64 = _ctx.get("enc_public_b64", "")
        sign_b64 = _ctx.get("sign_public_b64", "")
        did = _ctx.get("caller_did", _ctx.get("did", ""))
        return enc_b64, sign_b64, did

    async def on_ring(self, caller_name: str, session_id: str):
        """接收到呼叫——作为 responder 用对方公钥建立 cipher，并生成 salt 供 initiator 复用"""
        peer_enc_b64, peer_sign_b64, peer_did = self._peer_from_ctx()

        if peer_enc_b64 and peer_sign_b64:
            peer_enc = _unb64(peer_enc_b64)
            peer_sign = _unb64(peer_sign_b64)
            shared = compute_shared_secret(self.kp.enc_private, peer_enc)
            key, salt = derive_session_key(shared)
            self.cipher = SessionCipher(key, salt, self.kp.did, peer_did)
            # 保存给 initiator 复用——通过 ring 响应传回
            self.state._session_salt = salt
            self.state._session_key = key
            self.state._peer_did = peer_did
            self.state._peer_sign_public = peer_sign
            self.state._peer_enc_public = peer_enc
            self.e2ee_enabled = True
            print(f"  🔐 {self.state.name}: 加密会话已建立 (→ {peer_did})")
        else:
            # ⚠️ 静默明文降级 —— 必须是显式、带告警的，绝不静默
            print(f"  ⚠️⚠️ {self.state.name}: 对方未提供加密公钥，通信将<b>明文降级</b>（不安全）")
            print(f"        _call_context={getattr(self.state, '_call_context', {})}")

        self._start_ledger(session_id, peer_did, peer_sign_b64, is_initiator=False)

        if self._ring_hook:
            await self._ring_hook(caller_name, session_id)

    # ─── v0.2 账本：会话建立（v0.3 C2：规范化字段）───
    def _start_ledger(self, session_id: str, peer_did: str, peer_sign_b64: str,
                      is_initiator: Optional[bool] = None):
        """会话建立时起一本账本 + 记握手事件。失败不阻断通信（审计不能拖垮会话）。

        v0.3 C2：
          · initiator/responder 两端写**同一套**（发起方 DID / 响应方 DID）
          · 握手 nonce/fpr 统一取**发起方**视角
        """
        # lazy finalize：若上一个账本还没封存（responder 无显式 hangup 钩子），先封存它
        if self.ledger is not None:
            try:
                self.finalize_ledger(reason="superseded_by_new_session")
            except Exception as e:  # noqa: BLE001
                log.warn("ledger", "lazy finalize 失败", exc=e, session=session_id)
        try:
            from .ledger import SessionLedger
            role = self._is_initiator if is_initiator is None else is_initiator
            self._is_initiator = role
            # C2：两端写同一套 DID（发起方在前）
            if role:
                init_did, resp_did = self.kp.did, (peer_did or "")
            else:
                init_did, resp_did = (peer_did or ""), self.kp.did
            # C2：握手 nonce/fpr 统一取发起方视角（发起方产生 nonce；两侧记同一值）
            nonce = getattr(self.state, '_did_nonce', "") if role \
                else getattr(self.state, '_peer_did_nonce', getattr(self.state, '_did_nonce', ""))
            peer_fpr = "sha256:" + (peer_sign_b64[:16] if peer_sign_b64 else "")
            _ldir = getattr(self, "_ledger_dir_override", None)
            _lkw = {"ledger_dir": _ldir} if _ldir else {}
            self.ledger = SessionLedger(
                session_id=session_id or "unknown",
                initiator=init_did,
                responder=resp_did,
                channel="ws",
                peer_name=self.state.name,
                **_lkw,
            )
            self.ledger._is_initiator_view = role
            self.ledger.record_handshake(
                kex="X25519", cipher="ChaCha20-Poly1305", sig="Ed25519",
                did_verified=bool(peer_did),
                nonce=nonce,
                peer_fpr=peer_fpr,
            )
            self._frame_seq_in = 0
            self._frame_seq_out = 0
            self._sync_ledger_to_node()
        except Exception as e:  # noqa: BLE001
            log.error("ledger", "账本初始化失败（不阻断通信）", exc=e,
                      session=session_id, peer_did=peer_did)
            self.ledger = None

    async def on_accept(self):
        """接受方——用 ring 阶段已建立的 cipher，或从 peer 取盐"""
        # 如果 ring 时已建立 cipher，直接复用（responder 路径）
        if self.cipher:
            # responder 路径：账本已在 on_ring 里建（is_initiator=False）
            if self._accept_hook:
                await self._accept_hook()
            return

        # initiator（呼叫方）路径：从 ring 响应中拿到的 salt
        stored_salt = getattr(self.state, '_session_salt', None)
        peer_enc_b64, peer_sign_b64, peer_did = self._peer_from_ctx()

        if peer_enc_b64 and peer_sign_b64 and stored_salt is not None:
            peer_enc = _unb64(peer_enc_b64)
            peer_sign = _unb64(peer_sign_b64)
            shared = compute_shared_secret(self.kp.enc_private, peer_enc)
            # 复用 responder 的 salt，而不是生成新的
            key, _ = derive_session_key(shared, stored_salt)
            self.cipher = SessionCipher(key, stored_salt, self.kp.did, peer_did)
            self.state._peer_did = peer_did
            self.state._peer_sign_public = peer_sign
            self.state._peer_enc_public = peer_enc
            self.e2ee_enabled = True
            print(f"  🔐 {self.state.name}: 加密会话已建立 (→ {peer_did}) [复用 salt]")
        elif peer_enc_b64 and peer_sign_b64:
            # 兜底：无预存储 salt 时自己生成（旧协议兼容）
            peer_enc = _unb64(peer_enc_b64)
            peer_sign = _unb64(peer_sign_b64)
            shared = compute_shared_secret(self.kp.enc_private, peer_enc)
            key, salt = derive_session_key(shared)
            self.cipher = SessionCipher(key, salt, self.kp.did, peer_did)
            self.state._session_salt = salt
            self.state._peer_did = peer_did
            self.state._peer_sign_public = peer_sign
            self.state._peer_enc_public = peer_enc
            self.e2ee_enabled = True
            print(f"  ⚠️ {self.state.name}: 加密会话已建立 (→ {peer_did}) [降级: 无共享 salt]")

        # v0.3：initiator（呼叫方）也要建账本（is_initiator=True）
        # 之前此路径只建 cipher 不建账本 → 呼叫方无审计记录（v0.2 遗留缺口）
        if peer_enc_b64 and peer_sign_b64:
            sid = getattr(self.state, "session_id", "") or "unknown"
            if self.ledger is None and sid != "unknown":
                self._start_ledger(sid, peer_did, peer_sign_b64, is_initiator=True)

        if self._accept_hook:
            await self._accept_hook()

    # ─── 数据加解密 ───

    async def on_data(self, payload: str, seq: int, dtype: str, raw_bytes: Optional[bytes] = None):
        """
        解密入站数据 + 自动验证签名
        raw_bytes: 如果上层传入了 raw 字节（非字符串），从这里解密
        """
        decrypted = None

        # 不变量断言 #3：前缀 ↔ 加密一致性
        # 入站帧以 🔒 开头 ⇒ 发送端加密了；本端 e2ee_enabled 则期望加密。二者必须一致。
        has_enc_prefix = isinstance(payload, str) and payload.startswith("🔒")
        assert has_enc_prefix == self.e2ee_enabled, \
            (f"prefix/encryption invariant broken: frame_encrypted={has_enc_prefix}, "
             f"session enabled={self.e2ee_enabled} (seq={seq})")

        if self.cipher and self.e2ee_enabled:
            if raw_bytes:
                decrypted = self.cipher.decrypt(raw_bytes)
            else:
                # 尝试对 payload 做 base64 解码后解密
                # 兼容 encrypt_payload 的 "🔒{b64}" 前缀（on_data 需剥掉 🔒 前缀再解码）
                try:
                    _p = payload
                    if isinstance(_p, str) and _p.startswith("🔒"):
                        _p = _p[1:]
                    encrypted = _unb64(_p)
                    # 2026-09-19：先试对称棘轮解密（与发送端 ratchet_encrypt 配对），
                    # 失败再回退普通解密（兼容旧对端/旧数据）。
                    # ┌─ LEDGER 接入点 ②：降级记录（v0.2 · 本设计的灵魂）─────────────
                    # │ ⚠️ 10-09 那行「棘轮解密未命中，回退普通解密」就在下面这个分支。
                    # │ 必须在此处写一条带 downgrade_class 的帧事件：
                    # │   ledger.record_frame(direction="in", enc="plain",
                    # │       cipher_suite="ChaCha20-Poly1305", decrypt="fallback_plain",
                    # │       downgrade=True, reason=_classify_reason(...), payload=encrypted)
                    # │ reason 取值见 ledger.DOWNGRADE_CLASS_MAP：
                    # │   local_state_mismatch / reordered_frame / unexpected_cipher_change /
                    # │   ratchet_desync_prolonged / plaintext_downgrade / signature_verify_failed
                    # │ 同时正常命中分支（下方 decrypted is not None）也要记一条（H4 全量）。
                    # └──────────────────────────────────────────────────────────────
                    try:
                        decrypted = self.cipher.ratchet_decrypt(encrypted, seq)
                    except Exception as e:  # noqa: BLE001
                        # 棘轮未命中很常见（对端旧版/乱序）——debug 级，不是错误
                        log.debug("decrypt", "棘轮解密未命中，待回退", exc=e, seq=seq)
                        decrypted = None
                    if decrypted is None:
                        decrypted = self.cipher.decrypt(encrypted, seq)
                        if decrypted is not None:
                            print(f"  ⚠️ {self.state.name}: 棘轮解密未命中，回退普通解密 [{seq}]")
                            # ── 接入点②（灵魂）：降级记录 v0.2 ──
                            # reason 的细分：当前代码只能区分“棘轮未命中”，
                            # 归为 noise 级 local_state_mismatch（大概率正常）。
                            # 后续若要区分 reordered/desync，需在 cipher 层暴露更多信息。
                            self._record_frame(direction="in", enc="plain",
                                               decrypt="fallback_plain", downgrade=True,
                                               reason="local_state_mismatch", payload=encrypted)
                    else:
                        # H4 全量：正常命中也要记一条
                        self._record_frame(direction="in", enc="ratchet",
                                           decrypt="ok", downgrade=False, payload=encrypted)
                except Exception as e:  # noqa: BLE001
                    log.error("decrypt", "入站帧解密/记录失败（已丢弃该帧）", exc=e, seq=seq)
        else:
            decrypted = payload.encode("utf-8") if isinstance(payload, str) else payload

        if decrypted is None:
            print(f"  ⚠️ {self.state.name}: 解密失败 [{seq}]")
            return

        try:
            plaintext = decrypted.decode("utf-8")
        except UnicodeDecodeError:
            plaintext = str(decrypted)

        # 更新 payload（替换为明文）
        self.state._last_decrypted = plaintext

        print(f"  🔓 {self.state.name}: 解密 [{seq}] → \"{plaintext[:60]}\"")

        if self._data_hook:
            await self._data_hook(plaintext, seq, dtype)

    def _record_frame(self, *, direction: str, enc: str, decrypt: str,
                      downgrade: bool, reason: str = "", payload=None):
        """接入点②的统一入口。H4：正常/降级帧都记。失败不阻断通信。

        v0.3 C2：把 in/out 归一为**发送方 DID**（两端对同一帧一致）。
          · out = 本端发出 → sender = 本端 DID
          · in  = 对端发出 → sender = 对端 DID
        """
        if self.ledger is None:
            return
        try:
            if direction == "in":
                self._frame_seq_in += 1
            else:
                self._frame_seq_out += 1
            # C2 归一：发送方 DID（回落到 self/peer）
            led = self.ledger
            if direction == "out":
                sender = led.responder if getattr(led, "_is_initiator_view", True) is False \
                    else led.initiator
            else:
                sender = led.initiator if getattr(led, "_is_initiator_view", True) is False \
                    else led.responder
            self.ledger.record_frame(
                sender=sender or ("self" if direction == "out" else "peer"),
                enc=enc, cipher_suite="ChaCha20-Poly1305",
                decrypt=decrypt, downgrade=downgrade, reason=reason, payload=payload,
            )
        except Exception as e:  # noqa: BLE001
            log.error("ledger", "账本记帧失败（不阻断）", exc=e, direction=direction, seq=seq)

    def encrypt_payload(self, plaintext: str) -> str:
        """加密出站数据"""
        if not self.cipher or not self.e2ee_enabled:
            # ⚠️ 明文降级 —— 显式告警，绝不静默（AgentLink 曾踩：_call_context 无人赋值导致一直明文）
            print(f"  ⚠️⚠️ {self.state.name}: 无 cipher/未启用加密，出站数据<b>明文发送</b>（不安全）")
            return plaintext
        # 不变量断言 #2：DID 必须在 encrypt 前已解析（不能用占位符），否则 AEAD 绑定错
        # 占位符形态: 字面量 "placeholder" 或 "did:wba:IP-port"（p1.py 875 行 replace 而来）
        peer_did = self.state.peer_did or getattr(self.state, '_peer_did', '')
        _is_ph = (not peer_did) or peer_did == "placeholder" or peer_did.startswith("did:wba:")
        assert not _is_ph, \
            f"DID must be resolved before ring, got placeholder: {peer_did!r}"
        # 2026-09-19：启用对称棘轮（每条消息独立密钥）→ 单条密钥泄露不牵连其他消息。
        # 背景：此前 ratchet_encrypt/decrypt 虽已实现但零调用点（死代码），
        #       实际用的是 cipher.encrypt()，无任何棘轮 → 前向安全性不足。
        # 用对称棘轮 = 改动最小、无需改握手、两侧对称。
        try:
            encrypted, self._last_seq = self.cipher.ratchet_encrypt(plaintext.encode("utf-8"))
        except AttributeError:
            # 兼容旧 cipher（无棘轮方法）→ 回退普通加密（并告警）
            print(f"  ⚠️ {self.state.name}: cipher 无棘轮方法，回退普通加密")
            encrypted = self.cipher.encrypt(plaintext.encode("utf-8"))
            self._last_seq = None
        encrypted_b64 = _b64(encrypted)
        return f"🔒{encrypted_b64}"

    # ─── 挂接回调 ───

    def attach(self, on_ring=None, on_accept=None, on_data=None, on_hangup=None):
        """
        注入 P1 回调。
        用法:
          secure.attach(
            on_ring=my_ring_handler,
            on_accept=my_accept_handler,
            on_data=my_data_handler,
          )
          state.on_ring = secure.on_ring
          state.on_accept = secure.on_accept
          state.on_data = secure.on_data
        """
        if on_ring:
            self._ring_hook = on_ring
        if on_accept:
            self._accept_hook = on_accept
        if on_data:
            self._data_hook = on_data

    @property
    def is_secure(self) -> bool:
        return self.e2ee_enabled and self.cipher is not None

    # ─── v0.2 账本 → node 桥接（H1 签名交换）───
    def bind_node(self, node) -> None:
        """
        把签名密钥与账本访问权交给 AgentLinkNode，供会话结束时封存+签名交换。

        用法（在创建 node 后调一次）：
            node = AgentLinkNode(...)
            secure.bind_node(node)
        """
        try:
            node._sign_keypair = self.kp
            # 把账本挂到 node：node 在 _do_hangup 里读 self.ledger
            node.ledger = self.ledger
            # 会话建立后账本会新建 → 通过回调同步给 node
            self._node_ref = node
        except Exception as e:  # noqa: BLE001
            log.error("node", "bind_node 失败（账本将无法回传 node）", exc=e)

    def _sync_ledger_to_node(self):
        node = getattr(self, "_node_ref", None)
        if node is not None:
            node.ledger = self.ledger

    # ─── v0.2 账本：无 node 场景下的自封存（如 responder 脚本）───
    async def on_hangup(self, reason: str = "session_end", *args, **kwargs):
        """
        挂到 state.on_hangup 的会话结束回调（p1 会在会话断开时调用）。
        responder 脚本用法：state.on_hangup = secure.on_hangup
        职责：会话一断，立即封存账本（不依赖下次 on_ring 的 lazy finalize）。
        """
        self.finalize_ledger(reason=f"hangup:{reason}")

    def finalize_ledger(self, reason: str = "session_end") -> Optional[str]:
        """
        会话结束时封存账本（不依赖 AgentLinkNode）。
        适用：只用 create_secure_agent（state+secure）、无 node 的 responder。
        签名交换需 node/WS 信道，此处仅做：record_close + seal + save（单签）。
        返回 ledger_hash 或 None。
        """
        led = self.ledger
        if led is None:
            return None
        # v0.3：若已通过 WS 完成双签交换（ledger 已封存），不再单签覆盖
        if getattr(led, "_sealed", False):
            self.ledger = None
            return led.ledger_hash
        try:
            led.record_close(reason=reason)
            # 本端链尾 hash
            h_self = led.events[-1].hash
            # 我方签名（若有 keypair）
            my_sig = None
            try:
                from .crypto import sign_message
                my_sig = sign_message(self.kp.sign_private, h_self.encode()).hex()
            except Exception as e:  # noqa: BLE001
                log.error("ledger", "账本签名失败", exc=e, session=self.state.name)
            # 无 node/WS → 无法交换对端 hash → 单签（sig_object 待对端 hash 到齐方定）
            led.record_signature_exchange(
                initiator_sig_received=False, responder_sig_received=False,
                self_hash=h_self or "", peer_hash="",
                is_initiator=getattr(self, "_is_initiator", True),
            )
            ledger_hash = led.seal()
            # v0.3：按角色安放本端签名（单签场景）
            if getattr(self, "_is_initiator", True):
                led.attach_signatures(initiator_sig=my_sig or "", responder_sig="")
            else:
                led.attach_signatures(initiator_sig="", responder_sig=my_sig or "")
            led.save()
            print(f"  📒 {self.state.name}: 账本已封存 (hash={ledger_hash[:16]}…, 降级={led.downgrade_count}, 单签)")
            return ledger_hash
        except Exception as e:  # noqa: BLE001
            log.error("ledger", "账本封存失败", exc=e, session=self.state.name)
            return None
        finally:
            self.ledger = None


# ═══════════════════════════════════════════════
# 便捷工厂
# ═══════════════════════════════════════════════

def create_secure_agent(name: str, port: int,
                        keypair_path: Optional[str] = None,
                        did: Optional[str] = None) -> tuple:
    """
    创建一个加密 agent 并返回 (state, secure_manager, app_factory)
    用法:
      from .p1_shim import create_agent_app
      state, secure = create_secure_agent("Alice", 18763)
      state.on_ring = secure.on_ring
      state.on_accept = secure.on_accept
      state.on_data = secure.on_data
      app = create_agent_app(state)
    """
    from .p1_shim import AgentLinkState

    kp = None
    if keypair_path:
        try:
            kp = load_keypair(keypair_path)
        except FileNotFoundError:
            kp = generate_keypair(name)
            save_keypair(kp, keypair_path)

    actual_did = did or (kp.did if kp else f"did:agentlink:{name}")

    state = AgentLinkState(name=name, port=port, did=actual_did)
    secure = SecureSessionManager(state, keypair=kp)
    # 修复：state.did 必须与 crypto 身份 (secure.kp.did) 一致。
    # 否则 ring 响应会回传 name-based DID（did:agentlink:name），
    # 而 AEAD 关联数据 (AD) 用的是 kp.did（did:agentlink:name:<random>），
    # 两侧 AD 不对称 → 跨机解密必失败（对应历史缺陷 #4 的回归）。
    state.did = secure.kp.did

    return state, secure


# ═══════════════════════════════════════════════
# 信令服务注册辅助
# ═══════════════════════════════════════════════

def get_signal_registration_payload(secure: SecureSessionManager,
                                     state,
                                     signal_url: str) -> dict:
    """生成注册到信令服务的 payload"""
    auth = secure.get_auth_payload()
    return {
        "did": secure.kp.did,
        "name": state.name,
        "http_url": state.http_url,
        "ws_url": state.ws_url,
        "sign_public_b64": auth["sign_public_b64"],
        "enc_public_b64": auth["enc_public_b64"],
        "cert": auth["cert"],
        "metadata": {
            "protocol": "agentlink.session.v1",
            "agent_type": "AgentLink-P1",
            "features": ["e2ee", "websocket", "heartbeat", "channel", "presence"],
        },
    }


# ═══════════════════════════════════════════════
# 验证
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    import asyncio

    async def _test():
        print("🔐 AgentLink Secure Session 自测")
        print("=" * 50)

        from .p1_shim import AgentLinkState

        alice_state = AgentLinkState(name="Alice", port=18763, did="did:agentlink:alice")
        bob_state = AgentLinkState(name="Bob", port=18764, did="did:agentlink:bob")

        alice_secure = SecureSessionManager(alice_state)
        bob_secure = SecureSessionManager(bob_state)

        print(f"\n   Alice DID: {alice_secure.kp.did}")
        print(f"   Bob   DID: {bob_secure.kp.did}")

        # 模拟 E2EE 密钥协商
        # Alice 获取 Bob 的公钥，Bob 获取 Alice 的公钥
        alice_pub = alice_secure.get_auth_payload()
        bob_pub = bob_secure.get_auth_payload()

        print(f"\n   Alice pub keys: enc={alice_pub['enc_public_b64'][:16]}...")
        print(f"   Bob   pub keys: enc={bob_pub['enc_public_b64'][:16]}...")

        # Bob 用 Alice 的公钥建立 cipher（作为 responder）
        alice_enc = _unb64(alice_pub["enc_public_b64"])
        shared_bob = compute_shared_secret(bob_secure.kp.enc_private, alice_enc)
        key_bob, salt = derive_session_key(shared_bob)
        bob_secure.cipher = SessionCipher(key_bob, salt,
                                           bob_secure.kp.did, alice_secure.kp.did)
        bob_secure.state._session_salt = salt
        bob_secure.e2ee_enabled = True
        print(f"   Bob cipher: local={bob_secure.kp.did}, peer={alice_secure.kp.did}")

        # Alice 用 Bob 的公钥建立 cipher（作为 initiator，使用 Bob 的 salt）
        bob_enc = _unb64(bob_pub["enc_public_b64"])
        shared_alice = compute_shared_secret(alice_secure.kp.enc_private, bob_enc)
        key_alice, _ = derive_session_key(shared_alice, salt)
        alice_secure.cipher = SessionCipher(key_alice, salt,
                                             alice_secure.kp.did, bob_secure.kp.did)
        alice_secure.e2ee_enabled = True
        print(f"   Alice cipher: local={alice_secure.kp.did}, peer={bob_secure.kp.did}")

        # 验证两侧密钥一致
        assert key_bob == key_alice, f"密钥不一致: {_b64(key_bob)[:16]} != {_b64(key_alice)[:16]}"
        print(f"\n✅ 密钥协商一致: {_b64(key_alice)[:16]}...")

        # 验证两侧 AD 计算一致
        alice_ad = alice_secure.cipher.ad()
        bob_ad = bob_secure.cipher.ad()
        assert alice_ad == bob_ad, f"AD 不一致: {alice_ad} != {bob_ad}"
        print(f"✅ AD 一致: {alice_ad}")

        # 加密/解密
        plaintext = "白车报告出来了，车牌是套牌，黑色雅阁三天前报失。"
        encrypted_b64 = alice_secure.encrypt_payload(plaintext)
        assert encrypted_b64.startswith("🔒")
        raw_encrypted = _unb64(encrypted_b64[1:])

        print(f"\n📤 Alice 原文: {plaintext}")
        print(f"   密文: {encrypted_b64[:48]}...")

        decrypted_bytes = bob_secure.cipher.decrypt(raw_encrypted)
        decrypted = decrypted_bytes.decode("utf-8") if decrypted_bytes else None
        assert decrypted == plaintext, f"解密不匹配: {decrypted} != {plaintext}"
        print(f"📥 Bob 解密: {decrypted}")

        # 签名验证
        sig = sign_message(alice_secure.kp.sign_private, plaintext.encode())
        ok = verify_message(
            _unb64(alice_pub["sign_public_b64"]),
            plaintext.encode(), sig
        )
        assert ok
        assert not verify_message(
            _unb64(bob_pub["sign_public_b64"]),
            plaintext.encode(), sig
        )
        print(f"✅ 消息签名验证通过")

        # DID 绑定凭证验证
        cert = sign_did_binding(alice_secure.kp)
        assert verify_did_binding(cert)
        assert not verify_did_binding({**cert, "did": "did:agentlink:evil"})
        print(f"✅ DID 绑定凭证验证通过")

        print(f"\n{'='*50}")
        print("🎉 加密会话全部验证通过")

    asyncio.run(_test())
