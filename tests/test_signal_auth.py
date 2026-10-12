"""P0-4/P0-5 信令鉴权负向测试
================================
验证：
  · 离线消息接口拒绝「token 就是 DID」的伪鉴权
  · 签名 token 的时效/一次性 nonce/验签
  · 审计接口默认对本机放行、对非本机拒绝
"""
import time

import pytest

pytest.importorskip("fastapi")

from agentlink.crypto import generate_keypair, sign_message, _b64
from agentlink.signal import SignalServer


def _mk_server(tmp_path):
    return SignalServer(db_path=str(tmp_path / "sig.db"),
                        key_path=str(tmp_path / "key.json"))


def _sign_token(kp, nonce, ts=None):
    """按 signal.verify_token 的约定构造 token。"""
    import json
    body = json.dumps({"did": kp.did, "ts": ts if ts is not None else time.time(),
                       "nonce": nonce}, separators=(",", ":")).encode()
    sig = sign_message(kp.sign_private, b"agentlink-auth-v1:" + body)
    return _b64(body) + "." + _b64(sig)


def test_p04_fake_bearer_did_string_rejected(tmp_path):
    """P0-4：旧版「Bearer <DID 明文字符串>」必须被拒。"""
    srv = _mk_server(tmp_path)
    assert srv.verify_token("did:agentlink:eve:xxx") is None


def test_p04_valid_signed_token_roundtrip(tmp_path):
    """P0-4：挑战-响应签名 token 应通过，并消费 nonce。"""
    srv = _mk_server(tmp_path)
    kp = generate_keypair("alice")
    srv.register_agent(did=kp.did, name="alice", http_url="", ws_url="",
                       sign_public_b64=_b64(kp.sign_public),
                       enc_public_b64=_b64(kp.enc_public))
    nonce = srv.issue_challenge(kp.did)
    token = _sign_token(kp, nonce)
    assert srv.verify_token(token) == kp.did
    # 一次性：同一 token 不可复用
    assert srv.verify_token(token) is None


def test_p04_expired_token_rejected(tmp_path):
    """P0-4：过期 token 必须被拒。"""
    srv = _mk_server(tmp_path)
    kp = generate_keypair("bob")
    srv.register_agent(did=kp.did, name="bob", http_url="", ws_url="",
                       sign_public_b64=_b64(kp.sign_public),
                       enc_public_b64=_b64(kp.enc_public))
    nonce = srv.issue_challenge(kp.did)
    old = _sign_token(kp, nonce, ts=time.time() - 99999)
    assert srv.verify_token(old) is None


def test_p04_unregistered_did_rejected(tmp_path):
    """P0-4：未注册 DID（无公钥可验）应被拒。"""
    srv = _mk_server(tmp_path)
    kp = generate_keypair("ghost")
    nonce = srv.issue_challenge(kp.did)
    token = _sign_token(kp, nonce)
    assert srv.verify_token(token) is None


def test_p05_admin_localhost_allowed(tmp_path):
    """P0-5：本机请求放行审计接口。"""
    srv = _mk_server(tmp_path)

    class _C:
        host = "127.0.0.1"

    class _R:
        client = _C()
        headers = {}

    assert srv._require_admin(_R()) is True


def test_p05_admin_remote_denied_without_token(tmp_path):
    """P0-5：非本机且无 admin token → 拒绝。"""
    srv = _mk_server(tmp_path)

    class _C:
        host = "10.0.0.5"

    class _R:
        client = _C()
        headers = {}

    assert srv._require_admin(_R()) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
