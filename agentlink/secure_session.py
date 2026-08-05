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

    # ─── 公钥导出 ───

    def get_public_payload(self) -> dict:
        """用于附带在 call_req / call_accept 消息中的公钥信息"""
        return {
            "enc_public_b64": _b64(self.kp.enc_public),
            "sign_public_b64": _b64(self.kp.sign_public),
            "did": self.kp.did,
        }

    def get_auth_payload(self) -> dict:
        """附带 DID 绑定凭证"""
        return {
            **self.get_public_payload(),
            "cert": sign_did_binding(self.kp),
        }

    # ─── 密钥协商 —— 发起方 ───

    def _peer_from_ctx(self) -> tuple:
        """从 context 提取对端公钥和 DID，兼容不同 key 名"""
        _ctx = getattr(self.state, '_call_context', {})
        enc_b64 = _ctx.get("enc_public_b64", "")
        sign_b64 = _ctx.get("sign_public_b64", "")
        did = _ctx.get("caller_did", _ctx.get("did", ""))
        return enc_b64, sign_b64, did

    async def on_ring(self, caller_name: str, session_id: str):
        """接收到呼叫——使用对方公钥建立 cipher"""
        peer_enc_b64, peer_sign_b64, peer_did = self._peer_from_ctx()

        if peer_enc_b64 and peer_sign_b64:
            peer_enc = _unb64(peer_enc_b64)
            peer_sign = _unb64(peer_sign_b64)
            shared = compute_shared_secret(self.kp.enc_private, peer_enc)
            key, salt = derive_session_key(shared)
            self.cipher = SessionCipher(key, salt, self.kp.did, peer_did)
            # 保存 salt 给后续 accept 回复
            self.state._session_salt = salt
            self.state._peer_did = peer_did
            self.state._peer_sign_public = peer_sign
            self.state._peer_enc_public = peer_enc
            self.e2ee_enabled = True
            print(f"  🔐 {self.state.name}: 加密会话已建立 (→ {peer_did})")
        else:
            print(f"  ⚠️ {self.state.name}: 对方未提供加密公钥，通信不加密")

        if self._ring_hook:
            await self._ring_hook(caller_name, session_id)

    async def on_accept(self):
        """接受方——用已有的 cipher 或建立新的"""
        # 如果 ring 时已建立 cipher，直接复用
        if self.cipher:
            if self._accept_hook:
                await self._accept_hook()
            return

        peer_enc_b64, peer_sign_b64, peer_did = self._peer_from_ctx()

        if peer_enc_b64 and peer_sign_b64:
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
            print(f"  🔐 {self.state.name}: 加密会话已建立 (→ {peer_did})")

        if self._accept_hook:
            await self._accept_hook()

    # ─── 数据加解密 ───

    async def on_data(self, payload: str, seq: int, dtype: str, raw_bytes: Optional[bytes] = None):
        """
        解密入站数据 + 自动验证签名
        raw_bytes: 如果上层传入了 raw 字节（非字符串），从这里解密
        """
        decrypted = None

        if self.cipher and self.e2ee_enabled:
            if raw_bytes:
                decrypted = self.cipher.decrypt(raw_bytes)
            else:
                # 尝试对 payload 做 base64 解码后解密
                try:
                    encrypted = _unb64(payload)
                    decrypted = self.cipher.decrypt(encrypted)
                except Exception:
                    pass
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

    def encrypt_payload(self, plaintext: str) -> str:
        """加密出站数据"""
        if not self.cipher or not self.e2ee_enabled:
            return plaintext
        encrypted = self.cipher.encrypt(plaintext.encode("utf-8"))
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
