"""
AgentLink Crypto v2
X25519 DH + ChaCha20-Poly1305 + Ed25519 + X3DH + Double Ratchet
"""
from __future__ import annotations
import base64, json, os, time
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SALT_SIZE = 16
SIGN_MSG_PREFIX = b"agentlink-did-binding:v1:"

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def _unb64(s: str) -> bytes:
    return base64.b64decode(s)

def _json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()

@dataclass
class AgentKeyPair:
    did: str
    sign_private: bytes
    sign_public: bytes
    enc_private: bytes
    enc_public: bytes

    def sign_private_pem(self) -> str:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(self.sign_private)
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    def sign_public_pem(self) -> str:
        key = ed25519.Ed25519PublicKey.from_public_bytes(self.sign_public)
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def to_json(self) -> dict:
        return {
            "did": self.did,
            "sign_public_b64": _b64(self.sign_public),
            "enc_public_b64": _b64(self.enc_public),
        }

    def to_save(self) -> dict:
        return {
            "did": self.did,
            "sign_private_b64": _b64(self.sign_private),
            "sign_public_b64": _b64(self.sign_public),
            "enc_private_b64": _b64(self.enc_private),
            "enc_public_b64": _b64(self.enc_public),
        }

    @classmethod
    def from_save(cls, data: dict) -> AgentKeyPair:
        return cls(
            did=data["did"],
            sign_private=_unb64(data["sign_private_b64"]),
            sign_public=_unb64(data["sign_public_b64"]),
            enc_private=_unb64(data["enc_private_b64"]),
            enc_public=_unb64(data["enc_public_b64"]),
        )

def generate_keypair(name: str = "agent") -> AgentKeyPair:
    sign_key = ed25519.Ed25519PrivateKey.generate()
    enc_key = x25519.X25519PrivateKey.generate()
    sign_pub = sign_key.public_key()
    sign_pub_raw = sign_pub.public_bytes_raw()
    fp = _b64(sign_pub_raw)[:16]
    did = f"did:agentlink:{name}:{fp}"
    return AgentKeyPair(
        did=did,
        sign_private=sign_key.private_bytes_raw(),
        sign_public=sign_pub_raw,
        enc_private=enc_key.private_bytes_raw(),
        enc_public=enc_key.public_key().public_bytes_raw(),
    )

def compute_shared_secret(my_enc_private: bytes, peer_enc_public: bytes) -> bytes:
    my_key = x25519.X25519PrivateKey.from_private_bytes(my_enc_private)
    peer_key = x25519.X25519PublicKey.from_public_bytes(peer_enc_public)
    return my_key.exchange(peer_key)

def derive_session_key(shared_secret: bytes, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"agentlink-session-key-v1")
    return hkdf.derive(shared_secret), salt

def encrypt_message(session_key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
    aead = ChaCha20Poly1305(session_key)
    nonce = os.urandom(12)
    return nonce + aead.encrypt(nonce, plaintext, associated_data or b"")

def decrypt_message(session_key: bytes, encrypted: bytes, associated_data: Optional[bytes] = None) -> Optional[bytes]:
    try:
        aead = ChaCha20Poly1305(session_key)
        return aead.decrypt(encrypted[:12], encrypted[12:], associated_data or b"")
    except Exception:
        return None

def sign_message(sign_private: bytes, message: bytes) -> bytes:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(sign_private)
    return key.sign(SIGN_MSG_PREFIX + message)

def verify_message(sign_public: bytes, message: bytes, signature: bytes) -> bool:
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(sign_public)
        key.verify(signature, SIGN_MSG_PREFIX + message)
        return True
    except Exception:
        return False

def sign_did_binding(kp: AgentKeyPair) -> dict:
    ts = time.time()
    payload = _json_bytes({"did": kp.did, "timestamp": ts, "enc_public_b64": _b64(kp.enc_public)})
    sig = sign_message(kp.sign_private, payload)
    return {
        "did": kp.did, "sign_public_b64": _b64(kp.sign_public),
        "enc_public_b64": _b64(kp.enc_public), "timestamp": ts,
        "signature_b64": _b64(sig),
    }

def verify_did_binding(cert: dict) -> bool:
    """验证 DID 绑定凭证：签名有效性 + DID 指纹与 sign_public 绑定"""
    # 1. 验证签名
    payload = _json_bytes({"did": cert["did"], "timestamp": cert["timestamp"], "enc_public_b64": cert["enc_public_b64"]})
    if not verify_message(_unb64(cert["sign_public_b64"]), payload, _unb64(cert["signature_b64"])):
        return False
    # 2. 验证 DID 指纹：DID 最后一个冒号后的 16 字符应 = sign_public_b64 的前 16 字符
    did = cert.get("did", "")
    fp_from_did = did.rsplit(":", 1)[-1] if ":" in did else ""
    fp_from_sign = cert.get("sign_public_b64", "")[:16]
    if fp_from_did and fp_from_sign and fp_from_did != fp_from_sign:
        return False
    return True

def save_keypair(kp: AgentKeyPair, path: str):
    with open(path, "w") as f:
        json.dump(kp.to_save(), f, indent=2)
    # 设置文件权限 600（仅 owner 读写）
    os.chmod(path, 0o600)

def load_keypair(path: str) -> AgentKeyPair:
    with open(path) as f:
        return AgentKeyPair.from_save(json.load(f))


class SessionCipher:
    """E2EE session cipher: X3DH init + Ratchet encrypt/decrypt"""

    def __init__(self, session_key: bytes, salt: bytes, local_did: str, peer_did: str):
        self.session_key = session_key
        self.salt = salt
        self.local_did = local_did
        self.peer_did = peer_did
        self.seq = 0
        self._x3dh_ek_private: bytes = b""
        self._peer_ik: bytes = b""
        self._own_enc_private: bytes = b""

    @classmethod
    def establish_initiator(cls, my_kp: AgentKeyPair, peer_sign_public: bytes,
                             peer_enc_public: bytes, peer_did: str) -> Tuple[SessionCipher, bytes]:
        shared = compute_shared_secret(my_kp.enc_private, peer_enc_public)
        key, salt = derive_session_key(shared)
        return cls(key, salt, my_kp.did, peer_did), salt

    @classmethod
    def establish_responder(cls, my_kp: AgentKeyPair, peer_sign_public: bytes,
                             peer_enc_public: bytes, peer_did: str, salt: bytes) -> SessionCipher:
        shared = compute_shared_secret(my_kp.enc_private, peer_enc_public)
        key, _ = derive_session_key(shared, salt)
        return cls(key, salt, my_kp.did, peer_did)

    @classmethod
    def establish_x3dh_initiator(cls, my_kp: AgentKeyPair, peer_ik: bytes,
                                  peer_spk: bytes, peer_ek: bytes, peer_did: str) -> Tuple['SessionCipher', bytes]:
        """X3DH Initiator: IK_own·SPK_peer + EK·IK_peer + EK·SPK_peer"""
        ek = x25519.X25519PrivateKey.generate()
        ek_pub = ek.public_key().public_bytes_raw()
        ek_priv = ek.private_bytes_raw()
        dh1 = compute_shared_secret(my_kp.enc_private, peer_spk)      # IK_own · SPK_peer
        dh2 = compute_shared_secret(ek_priv, peer_ik)                  # EK_own · IK_peer
        dh3 = compute_shared_secret(ek_priv, peer_spk)                 # EK_own · SPK_peer
        combined = dh1 + dh2 + dh3
        key, salt = derive_session_key(combined)
        cipher = cls(key, salt, my_kp.did, peer_did)
        cipher._x3dh_ek_private = ek_priv
        cipher._own_enc_private = my_kp.enc_private
        cipher._peer_ik = peer_ik
        return cipher, ek_pub

    @classmethod
    def establish_x3dh_responder(cls, my_kp: AgentKeyPair, my_spk_private: bytes,
                                  peer_ik: bytes, peer_spk: bytes, peer_ek: bytes,
                                  peer_did: str, salt: bytes) -> 'SessionCipher':
        """X3DH Responder: SPK_own·IK_peer + SPK_own·EK_peer + SPK_own·SPK_peer
        三组 DH 与 Initiator 侧对称：
          Initiator dh1(IK_own·SPK_peer) ↔ Responder dh3(SPK_own·SPK_peer)
          Initiator dh2(EK·IK_peer)       ↔ Responder dh1(SPK_own·IK_peer)
          Initiator dh3(EK·SPK_peer)      ↔ Responder dh2(SPK_own·EK_peer)
        """
        dh1 = compute_shared_secret(my_spk_private, peer_ik)     # SPK_own · IK_peer
        dh2 = compute_shared_secret(my_spk_private, peer_ek)     # SPK_own · EK_peer
        dh3 = compute_shared_secret(my_spk_private, peer_spk)    # SPK_own · SPK_peer
        combined = dh1 + dh2 + dh3
        key, _ = derive_session_key(combined, salt)
        cipher = cls(key, salt, my_kp.did, peer_did)
        cipher._x3dh_ek_private = my_spk_private
        cipher._own_enc_private = my_kp.enc_private
        cipher._peer_ik = peer_ik
        return cipher

    def dh_ratchet_step(self, peer_new_pub: bytes) -> bytes:
        """Receives peer's new DH pub, generates new local keypair, derives new session_key"""
        if not peer_new_pub or len(peer_new_pub) != 32:
            raise ValueError("Invalid peer public key for DH ratchet")
        ek = x25519.X25519PrivateKey.generate()
        ek_pub = ek.public_key().public_bytes_raw()
        ek_priv = ek.private_bytes_raw()
        shared = compute_shared_secret(ek_priv, peer_new_pub)
        dids = sorted([self.local_did, self.peer_did])
        info = f"agentlink-dh-ratchet:{dids[0]}:{dids[1]}".encode()
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=self.salt, info=info)
        self.session_key = hkdf.derive(shared)
        self.seq = 0
        self._x3dh_ek_private = ek_priv
        return ek_pub

    def dh_ratchet_rotate(self, peer_pub_to_use: bytes) -> bytes:
        """Full DH ratchet rotation via peer public key, returns new local public key"""
        return self.dh_ratchet_step(peer_pub_to_use)

    def _ad_for_seq(self, seq: int) -> bytes:
        dids = sorted([self.local_did, self.peer_did])
        return f"agentlink:{dids[0]}:{dids[1]}:{seq}".encode()

    def ad(self) -> bytes:
        return self._ad_for_seq(self.seq)

    def encrypt(self, plaintext: bytes) -> bytes:
        self.seq += 1
        return encrypt_message(self.session_key, plaintext, self._ad_for_seq(self.seq))

    def decrypt(self, encrypted: bytes, seq: Optional[int] = None) -> Optional[bytes]:
        if seq is None:
            self.seq += 1
            seq = self.seq
        return decrypt_message(self.session_key, encrypted, self._ad_for_seq(seq))

    def ratchet_encrypt(self, plaintext: bytes) -> Tuple[bytes, int]:
        """Symmetric ratchet: per-message key via HKDF, forward secrecy"""
        self.seq += 1
        seq = self.seq
        msg_key = self._derive_message_key(seq)
        return encrypt_message(msg_key, plaintext, self._ad_for_seq(seq)), seq

    def ratchet_decrypt(self, encrypted: bytes, seq: int) -> Optional[bytes]:
        """Symmetric ratchet decrypt with per-message key"""
        msg_key = self._derive_message_key(seq)
        return decrypt_message(msg_key, encrypted, self._ad_for_seq(seq))

    def _derive_message_key(self, seq: int) -> bytes:
        info = f"agentlink-msg-key:seq={seq}".encode()
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=self.salt, info=info)
        return hkdf.derive(self.session_key)
