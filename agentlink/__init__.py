"""
AgentLink — Agent-to-Agent 实时通信协议
=======================================
7 原语搞定完整会话生命周期 + E2EE + 频道 + 在线状态

模块:
  agentlink.crypto          — 加密模块 (X25519 DH + ChaCha20-Poly1305 + Ed25519)
  agentlink.signal          — 信令服务 (FastAPI + SQLite + WebSocket)
  agentlink.secure_session  — 加密集成层 (对接 P1 状态机)
  agentlink.signal_client   — 信令客户端 (注册/发现/中继/离线)

依赖:
  pip install cryptography httpx websockets fastapi uvicorn
"""
from __future__ import annotations

from .crypto import (
    AgentKeyPair,
    SessionCipher,
    generate_keypair,
    load_keypair,
    save_keypair,
    compute_shared_secret,
    derive_session_key,
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_message,
    sign_did_binding,
    verify_did_binding,
    _b64,
    _unb64,
)

from .secure_session import (
    SecureSessionManager,
    create_secure_agent,
    get_signal_registration_payload,
)

from .signal_client import SignalClient

# P2: 频道 + Presence（集成自 agentlink_p2.py）
from .p2 import (
    ChannelRelay,
    PresenceFederator,
    P2ClientMixin,
    add_channel_relay,
    add_presence_federation,
    run_channel_relay,
)

__all__ = [
    # crypto
    "AgentKeyPair", "SessionCipher",
    "generate_keypair", "load_keypair", "save_keypair",
    "compute_shared_secret", "derive_session_key",
    "encrypt_message", "decrypt_message",
    "sign_message", "verify_message",
    "sign_did_binding", "verify_did_binding",
    "_b64", "_unb64",
    # secure_session
    "SecureSessionManager", "create_secure_agent",
    "get_signal_registration_payload",
    # signal_client
    "SignalClient",
]

__version__ = "0.1.0"
__protocol__ = "agentlink.session.v1"

# P2 — 频道中继 + Presence 联邦
# from .p2 import ChannelRelay, PresenceFederator, add_channel_relay, add_presence_federation, P2ClientMixin
__p2_available__ = False
try:
    from .p2 import ChannelRelay, add_channel_relay, add_presence_federation, P2ClientMixin, PresenceFederator
    __p2_available__ = True
except ImportError:
    class ChannelRelay: pass
    class P2ClientMixin: pass
