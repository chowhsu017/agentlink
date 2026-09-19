"""AgentLink 单元测试 — 适配 pip 包 API"""
import pytest, os, sys, time, tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agentlink import (
    AgentKeyPair, generate_keypair, load_keypair, save_keypair,
    compute_shared_secret, derive_session_key,
    encrypt_message, decrypt_message,
    sign_message, verify_message,
    sign_did_binding, verify_did_binding,
    SessionCipher, __version__,
    ChannelRelay,
)
from agentlink.crypto import _b64, _unb64


# ═══════════════════════════════════════════════
# 加密模块
# ═══════════════════════════════════════════════

class TestCrypto:
    def test_version(self):
        assert __version__ == "0.1.5"

    def test_generate_keypair(self):
        kp = generate_keypair("Test")
        assert kp.did.startswith("did:agentlink:Test:")
        assert len(kp.enc_private) == 32
        assert len(kp.enc_public) == 32
        assert len(kp.sign_private) == 32
        assert len(kp.sign_public) == 32
        assert kp.enc_private != b"\x00" * 32  # 不是空值

    def test_dh_key_exchange(self):
        alice = generate_keypair("Alice")
        bob = generate_keypair("Bob")
        shared_a = compute_shared_secret(alice.enc_private, bob.enc_public)
        shared_b = compute_shared_secret(bob.enc_private, alice.enc_public)
        assert shared_a == shared_b, "DH 密钥不一致"
        assert len(shared_a) == 32

    def test_session_key_derivation(self):
        alice = generate_keypair("Alice")
        bob = generate_keypair("Bob")
        shared = compute_shared_secret(alice.enc_private, bob.enc_public)
        # 相同的 salt 产生相同的密钥
        salt = b"test_salt_16Byte!"
        sk1, _ = derive_session_key(shared, salt)
        sk2, _ = derive_session_key(shared, salt)
        assert sk1 == sk2, "会话密钥派生不一致"
        assert len(sk1) == 32

    def test_encrypt_decrypt(self):
        kp = generate_keypair("T")
        bob = generate_keypair("B")
        shared = compute_shared_secret(kp.enc_private, bob.enc_public)
        sk, _ = derive_session_key(shared)
        plaintext = b"Hello, AgentLink!"
        encrypted = encrypt_message(sk, plaintext)
        assert encrypted != plaintext
        decrypted = decrypt_message(sk, encrypted)
        assert decrypted == plaintext

    def test_encrypt_with_aad(self):
        kp = generate_keypair("T")
        bob = generate_keypair("B")
        shared = compute_shared_secret(kp.enc_private, bob.enc_public)
        sk, _ = derive_session_key(shared)
        aad = b"session-001"
        plain = b"Important case data"
        enc = encrypt_message(sk, plain, aad)
        dec = decrypt_message(sk, enc, aad)
        assert dec == plain
        # 错误 AAD 应返回 None
        assert decrypt_message(sk, enc, b"wrong-aad") is None

    def test_tampered_message(self):
        kp = generate_keypair("T")
        bob = generate_keypair("B")
        shared = compute_shared_secret(kp.enc_private, bob.enc_public)
        sk, _ = derive_session_key(shared)
        enc = encrypt_message(sk, b"secret message")
        tampered = bytearray(enc)
        tampered[10] ^= 0xFF  # 篡改一个字节
        assert decrypt_message(sk, bytes(tampered)) is None

    def test_sign_verify(self):
        kp = generate_keypair("T")
        msg = b"This message is signed by Alice"
        sig = sign_message(kp.sign_private, msg)
        assert verify_message(kp.sign_public, msg, sig)
        assert not verify_message(kp.sign_public, b"wrong message", sig)
        fake_sig = bytes([0] * 64)
        assert not verify_message(kp.sign_public, msg, fake_sig)

    def test_did_binding(self):
        kp = generate_keypair("T")
        creds = sign_did_binding(kp)
        assert "did" in creds
        assert "enc_public_b64" in creds
        assert "signature_b64" in creds
        assert verify_did_binding(creds)
        bad = dict(creds)
        bad["did"] = "did:attacker"
        assert not verify_did_binding(bad)

    def test_session_cipher(self):
        """模拟 Alice → Bob 的加密通信"""
        alice = generate_keypair("Alice")
        bob = generate_keypair("Bob")
        shared = compute_shared_secret(alice.enc_private, bob.enc_public)
        sk, salt = derive_session_key(shared)
        # Alice 侧加密器、Bob 侧解密器（各维护独立 seq）
        alice_cipher = SessionCipher(sk, salt, alice.did, bob.did)
        bob_cipher = SessionCipher(sk, salt, bob.did, alice.did)
        plaintext = b"End-to-end encrypted"
        enc = alice_cipher.encrypt(plaintext)
        dec = bob_cipher.decrypt(enc)
        assert dec == plaintext
        assert dec == plaintext

    def test_save_load_keypair(self):
        kp = generate_keypair("SaveTest")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
            save_keypair(kp, path)
        try:
            loaded = load_keypair(path)
            assert loaded.did == kp.did
            assert loaded.enc_private == kp.enc_private
            assert loaded.enc_public == kp.enc_public
            assert loaded.sign_private == kp.sign_private
            assert loaded.sign_public == kp.sign_public
        finally:
            os.unlink(path)

    def test_b64_roundtrip(self):
        data = b"\x00\x01\x02\xFF\xFE\xFD" * 10
        assert _unb64(_b64(data)) == data


# ═══════════════════════════════════════════════
# 频道中继模块
# ═══════════════════════════════════════════════

class TestRatchet:
    """对称棘轮 / 前向安全回归测试（2026-09-19 加：修复棘轮死代码后固化行为）"""

    def _pair(self):
        a = generate_keypair("Alice")
        b = generate_keypair("Bob")
        shared = compute_shared_secret(a.enc_private, b.enc_public)
        key, salt = derive_session_key(shared)
        return (SessionCipher(key, salt, a.did, b.did),
                SessionCipher(key, salt, b.did, a.did))

    def test_ratchet_roundtrip(self):
        ca, cb = self._pair()
        for i in range(5):
            enc, seq = ca.ratchet_encrypt(f"msg{i}".encode())
            assert cb.ratchet_decrypt(enc, seq) == f"msg{i}".encode()

    def test_per_message_key_unique(self):
        """每条消息密钥必须不同（对称棘轮的核心）"""
        ca, _ = self._pair()
        keys = set()
        for i in range(10):
            ca.ratchet_encrypt(b"x")
            keys.add(ca._derive_message_key(ca.seq))
        assert len(keys) == 10, "消息密钥出现重复，棘轮失效"

    def test_forward_secrecy(self):
        """前向安全：拿到某条消息密钥，不能解另一条消息"""
        ca, cb = self._pair()
        enc0, seq0 = ca.ratchet_encrypt(b"secret-0")
        enc1, seq1 = ca.ratchet_encrypt(b"secret-1")
        leaked_key = ca._derive_message_key(seq0)   # 冒充：第0条密钥泄露
        assert decrypt_message(leaked_key, enc1, ca._ad_for_seq(seq1)) is None, \
            "旧消息密钥能解新消息 → 前向安全不成立"


class TestChannelRelay:
    def test_create_channel(self):
        r = ChannelRelay(db_path=":memory:")
        assert r.create_channel("c1", "C1", "did:a")["result"] == "created"

    def test_duplicate_channel(self):
        r = ChannelRelay(db_path=":memory:")
        r.create_channel("c1", "C1", "did:a")
        assert r.create_channel("c1", "C1 again", "did:a")["result"] == "exists"

    def test_list_channels(self):
        r = ChannelRelay(db_path=":memory:")
        r.create_channel("c1", "C1", "did:a")
        r.create_channel("c2", "C2", "did:b")
        assert len(r.list_channels()) == 2

    def test_get_channel(self):
        r = ChannelRelay(db_path=":memory:")
        r.create_channel("c1", "C1", "did:a")
        ch = r.get_channel("c1")
        assert ch is not None and ch["name"] == "C1"
        assert r.get_channel("nonexistent") is None

    def test_delete_channel(self):
        r = ChannelRelay(db_path=":memory:")
        r.create_channel("c1", "C1", "did:a")
        assert r.delete_channel("c1")
        assert r.get_channel("c1") is None

    def test_join_members(self):
        r = ChannelRelay(db_path=":memory:")
        r.create_channel("c1", "C1", "did:creator")
        r.join_channel("c1", "did:alice")
        r.join_channel("c1", "did:bob")
        dids = {m["did"] for m in r.get_members("c1")}
        assert "did:alice" in dids
        assert "did:bob" in dids
        assert "did:creator" in dids

    def test_leave_channel(self):
        r = ChannelRelay(db_path=":memory:")
        r.create_channel("c1", "C1", "did:a")
        r.leave_channel("c1", "did:a")
        assert len(r.get_members("c1")) == 0

    def test_channel_key(self):
        # 2026-09-19 修：derive_channel_key 现为“无 E2EE 则返回 None”（防假密钥）。
        # 原测试假设无 e2ee 频道也返回 32 字节密钥 —— 那是旧行为。
        r = ChannelRelay(db_path=":memory:")
        # 非 E2EE 频道：应返回 None（不生成假密钥）
        r.create_channel("c1", "C1", "did:a")
        assert r.derive_channel_key("c1") is None
        # 未创建的频道：也应为 None
        assert r.derive_channel_key("c-nonexist") is None
        # 幂等：多次调用结果一致
        assert r.derive_channel_key("c1") == r.derive_channel_key("c1")

    def test_channel_messages(self):
        r = ChannelRelay(db_path=":memory:")
        r.create_channel("c1", "C1", "did:a")
        now = time.time()
        r.conn.execute(
            "INSERT INTO channel_messages(channel_id,sender_did,type,payload,encrypted,ts) VALUES(?,?,?,?,?,?)",
            ("c1", "did:a", "text", "hello", 0, now)
        )
        r.conn.execute(
            "INSERT INTO channel_messages(channel_id,sender_did,type,payload,encrypted,ts) VALUES(?,?,?,?,?,?)",
            ("c1", "did:b", "text", "world", 0, now + 1)
        )
        r.conn.commit()
        hist = r.get_history("c1", 10)
        assert len(hist) == 2
        # DESC order — latest first
        assert hist[0]["payload"] == "hello"
        assert hist[1]["payload"] == "world"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
