"""P1 加固回归测试（v0.3.1）
==========================
覆盖：
  · P1-3 状态机：合法转换通过、非法转换抛 StateError
  · P1-5 DID 凭证：过期 / 挑战 nonce 不匹配 / 篡改非ce 均失败
  · P1-7 防重放：同一 seq 第二次解密返回 None
  · P1-1 日志：logbook 可导入且分级可用
"""
import time

import pytest

from agentlink.crypto import (
    generate_keypair, sign_did_binding, verify_did_binding,
    SessionCipher, compute_shared_secret, derive_session_key,
)


# ─── P1-3 状态机 ───

def test_p13_state_machine_legal_transitions():
    from agentlink.node import AgentLinkNode, NodeState
    n = AgentLinkNode("t", 1)
    assert n.status == "idle"
    n._set_state(NodeState.RINGING)
    n._set_state(NodeState.IN_SESSION)
    n._set_state(NodeState.IDLE)
    assert n.status == "idle"


def test_p13_state_machine_illegal_transition_raises():
    from agentlink.node import AgentLinkNode, NodeState, StateError
    n = AgentLinkNode("t", 1)
    # IDLE 不能直接跳 IN_SESSION
    with pytest.raises(StateError):
        n._set_state(NodeState.IN_SESSION)


def test_p13_status_setter_backcompat():
    from agentlink.node import AgentLinkNode
    n = AgentLinkNode("t", 1)
    n.status = "ringing"           # 旧代码直接赋字符串
    assert n.status == "ringing"


# ─── P1-5 DID 凭证时效/挑战 ───

def test_p15_fresh_cert_passes():
    kp = generate_keypair("alice")
    cert = sign_did_binding(kp, nonce="n123")
    assert verify_did_binding(cert, expected_nonce="n123") is True


def test_p15_expired_cert_rejected():
    kp = generate_keypair("alice")
    cert = sign_did_binding(kp)
    # 伪造一个 1 小时前的 timestamp 并重签 → 超 5 分钟窗口
    cert["timestamp"] = time.time() - 3600
    from agentlink.crypto import sign_message, _json_bytes, _b64, _unb64
    payload = _json_bytes({"did": kp.did, "timestamp": cert["timestamp"],
                           "enc_public_b64": cert["enc_public_b64"],
                           "nonce": cert.get("nonce", "")})
    cert["signature_b64"] = _b64(sign_message(kp.sign_private, payload))
    assert verify_did_binding(cert) is False


def test_p15_wrong_nonce_rejected():
    kp = generate_keypair("alice")
    cert = sign_did_binding(kp, nonce="real")
    assert verify_did_binding(cert, expected_nonce="forged") is False


def test_p15_tampered_nonce_breaks_sig():
    """把 nonce 改掉但不动签名 → 验签失败。"""
    kp = generate_keypair("alice")
    cert = sign_did_binding(kp, nonce="real")
    cert["nonce"] = "tampered"
    assert verify_did_binding(cert) is False


# ─── P1-7 防重放 ───

def _mk_cipher_pair():
    a = generate_keypair("a")
    b = generate_keypair("b")
    shared = compute_shared_secret(a.enc_private, b.enc_public)
    key, salt = derive_session_key(shared)
    ca = SessionCipher(key, salt, a.did, b.did)
    cb = SessionCipher(key, salt, b.did, a.did)
    return ca, cb


def test_p17_replay_same_seq_rejected():
    ca, cb = _mk_cipher_pair()
    enc, seq = ca.ratchet_encrypt(b"hello")
    # 第一次解密成功
    assert cb.ratchet_decrypt(enc, seq) == b"hello"
    # 重放同一 seq → 拒绝（返回 None）
    assert cb.ratchet_decrypt(enc, seq) is None


# ─── P1-1 日志 ───

def test_p11_logbook_importable():
    from agentlink.logbook import log
    log.warn("test", "ok", exc=ValueError("x"))  # 不应抛异常
