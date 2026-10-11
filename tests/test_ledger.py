"""
AgentLink v0.2 会话账本 — 端到端集成测试
========================================

覆盖设计稿 docs/会话可审计MVP设计-v0.2-20261011.md §五 的验证 1/2/3：
  验证1：正常会话 → downgrade_count==0 + 双签齐备 + signature_exchange 事件存在
  验证2：降级帧 → downgrade 分级正确
  验证3：单方篡改 → 哈希链断 / 缺对方签名 → invalid（H1 核心）

另测：签名交换全链路（模拟 node._finalize_ledger 的收发）
"""

import asyncio
import os
import tempfile

import pytest

from agentlink.ledger import SessionLedger, classify_downgrade, compute_sig_object


def _make_ledger(sid="t1", d=None):
    return SessionLedger(
        session_id=sid,
        initiator="did:agentlink:node-a:AAA",
        responder="did:agentlink:node-b:BBB",
        ledger_dir=d or tempfile.mkdtemp(),
    )


# ─── 验证 1：正常会话 ───

def test_normal_session_no_downgrade():
    led = _make_ledger("normal")
    led.record_handshake(kex="X25519", cipher="ChaCha20-Poly1305", sig="Ed25519",
                         did_verified=True, nonce="n1", peer_fpr="fpr1")
    # 3 条正常帧（H4：都要记）
    for _ in range(3):
        led.record_frame(direction="in", enc="ratchet", cipher_suite="ChaCha20-Poly1305",
                         decrypt="ok", payload=b"ok-frame")
    led.record_close(reason="user_hangup", frames_in=3, frames_out=0)
    led.record_signature_exchange(initiator_sig_received=True, responder_sig_received=True)
    led.attach_signatures(initiator_sig="SIG_I", responder_sig="SIG_R")
    led.seal()

    # downgrade_count == 0
    assert led.downgrade_count == 0
    assert led.downgrade_count_by_class == {"noise": 0, "suspicious": 0, "critical": 0}
    # 全量记录：4 条 frame？不，3 条 frame + handshake + close + sig_exchange = 6 事件
    frame_events = [e for e in led.events if e.type == "frame"]
    assert len(frame_events) == 3, "H4: 正常帧也必须记录"
    # signature_exchange 事件存在
    assert any(e.type == "signature_exchange" for e in led.events)
    # 双签齐备 + 校验通过
    r = led.verify(verifier=lambda s, h, role: True)
    assert r["ok"] and r["both_sigs_present"], r


# ─── 验证 2：降级分级 ───

@pytest.mark.parametrize("reason,expected_class", [
    ("local_state_mismatch", "noise"),
    ("reordered_frame", "noise"),
    ("unexpected_cipher_change", "suspicious"),
    ("ratchet_desync_prolonged", "suspicious"),
    ("plaintext_downgrade", "critical"),
    ("signature_verify_failed", "critical"),
    ("never_seen_reason", "suspicious"),  # 未知 → 保守归 suspicious
])
def test_downgrade_classification(reason, expected_class):
    assert classify_downgrade(reason) == expected_class


def test_downgrade_recorded_and_counted():
    led = _make_ledger("dg")
    led.record_handshake(kex="X25519", cipher="CC20", sig="Ed25519", did_verified=True)
    led.record_frame(direction="in", enc="plain", cipher_suite="CC20",
                     decrypt="fallback_plain", downgrade=True,
                     reason="plaintext_downgrade", payload=b"x")
    assert led.downgrade_count == 1
    assert led.downgrade_count_by_class["critical"] == 1
    ev = [e for e in led.events if e.type == "frame"][0]
    assert ev.detail["downgrade"] is True
    assert ev.detail["downgrade_class"] == "critical"
    assert ev.detail["downgrade_reason"] == "plaintext_downgrade"


# ─── 验证 3：篡改检测（H1 核心）───

def test_tamper_middle_event_breaks_chain():
    led = _make_ledger("tamper")
    led.record_handshake(kex="X25519", cipher="CC20", sig="Ed25519", did_verified=True)
    led.record_frame(direction="in", enc="ratchet", cipher_suite="CC20", decrypt="ok", payload=b"a")
    led.record_frame(direction="in", enc="ratchet", cipher_suite="CC20", decrypt="ok", payload=b"b")
    led.record_close(reason="x")
    led.attach_signatures(initiator_sig="SIG_I", responder_sig="SIG_R")
    led.seal()
    # 先确认干净状态通过
    assert led.verify(verifier=lambda s, h, r: True)["ok"] is True
    # 篡改中间一条
    led.events[1].detail["payload_sha256"] = "sha256:TAMPERED"
    r = led.verify()
    assert r["ok"] is False
    assert "hash chain broken" in r["reason"]


def test_missing_peer_signature_is_invalid():
    """H1 核心：单方出示（缺对方签名）→ invalid"""
    led = _make_ledger("missing")
    led.record_handshake(kex="X25519", cipher="CC20", sig="Ed25519", did_verified=True)
    led.record_close(reason="x")
    led.attach_signatures(initiator_sig="SIG_I", responder_sig="")  # 缺对方
    led.seal()
    r = led.verify()
    assert r["ok"] is False
    assert r["both_sigs_present"] is False
    assert "missing signature" in r["reason"]


def test_wrong_peer_signature_fails_verification():
    """对方签名对不上（=有人篡改）→ 验签失败"""
    led = _make_ledger("wrongsig")
    led.record_handshake(kex="X25519", cipher="CC20", sig="Ed25519", did_verified=True)
    led.record_close(reason="x")
    led.attach_signatures(initiator_sig="SIG_I", responder_sig="SIG_R")
    led.seal()
    r = led.verify(verifier=lambda s, h, role: s == "SIG_I")  # 只认对的一方
    assert r["ok"] is False
    assert "verification failed" in r["reason"]


# ─── 落盘 / 加载往返 ───

def test_save_and_load_roundtrip():
    d = tempfile.mkdtemp()
    led = _make_ledger("roundtrip", d)
    led.record_handshake(kex="X25519", cipher="CC20", sig="Ed25519", did_verified=True)
    led.record_frame(direction="in", enc="plain", cipher_suite="CC20", decrypt="fallback_plain",
                     downgrade=True, reason="local_state_mismatch", payload=b"p")
    led.record_close(reason="ws_disconnect")
    led.attach_signatures(initiator_sig="SIG_I", responder_sig="SIG_R")
    led.seal()
    p1, p2 = led.save()
    assert os.path.exists(p1) and os.path.exists(p2)

    led2 = SessionLedger.load("roundtrip", d)
    assert len(led2.events) == len(led.events)
    assert led2.downgrade_count == 1
    assert led2.downgrade_count_by_class["noise"] == 1
    assert led2.ledger_hash == led.ledger_hash
    # 加载后校验仍通过
    r = led2.verify(verifier=lambda s, h, role: True)
    assert r["ok"] is True, r


# ─── 签名交换全链路（模拟 node._finalize_ledger 的双向收发）───

def test_signature_exchange_roundtrip():
    """
    模拟两方各自封账 → 互发签名 → 各自入账 → 双方 verify 都通过
    """
    d_a, d_b = tempfile.mkdtemp(), tempfile.mkdtemp()

    # 双方各自建账本（同一会话 id，视角不同）
    a = _make_ledger("sess-x", d_a)
    b = _make_ledger("sess-x", d_b)
    for led in (a, b):
        led.record_handshake(kex="X25519", cipher="CC20", sig="Ed25519", did_verified=True)
        led.record_frame(direction="in", enc="ratchet", cipher_suite="CC20", decrypt="ok", payload=b"m")
        led.record_close(reason="user_hangup")
        led.seal()

    # 交换前的 hash 应一致（同样事件序列）
    assert a.ledger_hash == b.ledger_hash

    # 互发签名（模拟 WS 交换）
    sig_a, sig_b = "ED25519_A", "ED25519_B"
    a.attach_signatures(initiator_sig=sig_a, responder_sig=sig_b)
    b.attach_signatures(initiator_sig=sig_a, responder_sig=sig_b)

    # 双方各自 verify 都应通过（双签齐备 + 验签）
    for led in (a, b):
        r = led.verify(verifier=lambda s, h, role: s in (sig_a, sig_b))
        assert r["ok"] is True, (led.session_id, r)


# ═══════════════════════════════════════════════════════════════
# v0.3（C1/C2/C3）—— 跨机账本一致性
# 设计稿：docs/会话可审计MVP设计-v0.3-20261012.md §五 验证 A/B/C/D
# ═══════════════════════════════════════════════════════════════

import time as _time


def _make_side(sid, d, who, is_init):
    """造一端账本：视角不同（direction/nonce/fpr/ts 不同）→ 两本 hash 天然不同。"""
    _time.sleep(1.05)  # 保证 ts 不同
    led = SessionLedger(
        session_id=sid,
        # C2：initiator/responder 两端写同一套（发起方 DID / 响应方 DID）
        initiator="did:agentlink:node-a:AAA",
        responder="did:agentlink:node-b:BBB",
        ledger_dir=d,
    )
    led._is_initiator_view = is_init
    led.record_handshake(kex="X25519", cipher="ChaCha20-Poly1305", sig="Ed25519",
                         did_verified=True, nonce=f"{who}-nonce", peer_fpr=f"fpr-{who}")
    # 同一帧：两端 sender 归一为**发送方 DID**（C2 绝对值，两端一致）
    led.record_frame(sender="did:agentlink:node-a:AAA", enc="ratchet",
                     cipher_suite="ChaCha20-Poly1305", decrypt="ok", payload=b"hi")
    led.record_frame(sender="did:agentlink:node-b:BBB", enc="plain",
                     cipher_suite="ChaCha20-Poly1305", decrypt="fallback_plain",
                     downgrade=True, reason="local_state_mismatch", payload=b"reply")
    led.record_close(reason="user_hangup" if is_init else "hangup:done", frames_in=1, frames_out=1)
    return led


def test_v03_verify_A_honest_cross_machine_passes():
    """验证 A（修假阴性）：诚实跨机会话 → 双签校验通过。"""
    d_a, d_b = tempfile.mkdtemp(), tempfile.mkdtemp()
    A = _make_side("v3-A", d_a, "alice", True)
    H_A = A.events[-1].hash
    B = _make_side("v3-A", d_b, "bob", False)
    H_B = B.events[-1].hash

    # 诚实会话两本账本 hash 天生不同（v0.2 的坑）
    assert H_A != H_B, "测试前提：两本账本应不同视角"

    # v0.3：两端算出同一 sig_object
    obj_a = compute_sig_object(H_A, H_B, is_initiator=True)
    obj_b = compute_sig_object(H_B, H_A, is_initiator=False)
    assert obj_a == obj_b, "C1：定序错误，两端 sig_object 应一致"

    for led, is_init, h_self, h_peer in ((A, True, H_A, H_B), (B, False, H_B, H_A)):
        led.record_signature_exchange(initiator_sig_received=True, responder_sig_received=True,
                                      self_hash=h_self, peer_hash=h_peer, is_initiator=is_init)
        led.seal()
        led.attach_signatures(initiator_sig="ED25519_I", responder_sig="ED25519_R")

    # 核心：诚实会话双向验签均通过（v0.2 此处必然 False）
    ver = lambda s, obj, role: True
    ra = A.verify(verifier=ver)
    rb = B.verify(verifier=ver, is_initiator=False)
    assert ra["ok"] and ra["sig_object_ok"], ra
    assert rb["ok"] and rb["sig_object_ok"], rb
    assert ra["sig_verified"] and rb["sig_verified"]


def test_v03_verify_B_tamper_self_ledger_detected():
    """验证 B：单方改本端账本 → 链断 / sig_object 变 → 验不过。"""
    d_a = tempfile.mkdtemp()
    A = _make_side("v3-B", d_a, "alice", True)
    H_A = A.events[-1].hash
    H_B = "sha256:" + "b" * 64  # 任意对端 hash
    A.record_signature_exchange(initiator_sig_received=True, responder_sig_received=True,
                                self_hash=H_A, peer_hash=H_B, is_initiator=True)
    A.seal()
    A.attach_signatures(initiator_sig="ED25519_I", responder_sig="ED25519_R")
    assert A.verify(verifier=lambda s, o, r: True)["ok"] is True
    # 篡改中间一条 → 链断
    A.events[1].detail["payload_sha256"] = "sha256:TAMPERED"
    r = A.verify()
    assert r["ok"] is False
    assert "hash chain broken" in r["reason"]


def test_v03_verify_C_forks_detected():
    """验证 C（C3 防分叉）：单独改 peer_hash → sig_object 不匹配 → 暴露。"""
    d_a = tempfile.mkdtemp()
    A = _make_side("v3-C", d_a, "alice", True)
    H_A = A.events[-1].hash
    H_B = "sha256:" + "c" * 64
    A.record_signature_exchange(initiator_sig_received=True, responder_sig_received=True,
                                self_hash=H_A, peer_hash=H_B, is_initiator=True)
    A.seal()
    A.attach_signatures(initiator_sig="ED25519_I", responder_sig="ED25519_R")
    assert A.verify(verifier=lambda s, o, r: True)["ok"] is True
    # 改对端 hash（v0.2 此字段收到即弃 → 改不了任何东西；v0.3 会暴露）
    A.peer_hash = "sha256:" + "0" * 64
    r = A.verify()
    assert r["ok"] is False
    assert r["sig_object_ok"] is False
    assert "sig_object mismatch" in r["reason"]


def test_v03_verify_D_normalized_fields_align():
    """验证 D（C2）：两端对应字段值一致（sender 归一）。"""
    d_a, d_b = tempfile.mkdtemp(), tempfile.mkdtemp()
    A = _make_side("v3-D", d_a, "alice", True)
    B = _make_side("v3-D", d_b, "bob", False)
    # initiator/responder 两端一致（C2 规范化）
    assert A.initiator == B.initiator
    assert A.responder == B.responder
    # 同一帧 sender 归一一致（发送方 DID），非 in/out 相反
    far = [e.detail for e in A.events if e.type == "frame"]
    fbr = [e.detail for e in B.events if e.type == "frame"]
    assert [f["sender"] for f in far] == [f["sender"] for f in fbr]
    assert all(f["sender"].startswith("did:") for f in far)
    # 旧 direction 字段不再出现于新账本
    assert all("direction" not in f for f in far)


def test_v03_sig_object_saved_and_loaded():
    """v0.3 落盘：sig_object/peer_hash 进 .sig，load 后可复验。"""
    d = tempfile.mkdtemp()
    A = _make_side("v3-save", d, "alice", True)
    H_A = A.events[-1].hash
    H_B = "sha256:" + "d" * 64
    A.record_signature_exchange(initiator_sig_received=True, responder_sig_received=True,
                                self_hash=H_A, peer_hash=H_B, is_initiator=True)
    A.seal()
    A.attach_signatures(initiator_sig="ED25519_I", responder_sig="ED25519_R")
    A.save()
    A2 = SessionLedger.load("v3-save", d)
    assert A2.sig_object and A2.peer_hash and A2.self_hash
    r = A2.verify(verifier=lambda s, o, r: True)
    assert r["ok"] is True, r


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
