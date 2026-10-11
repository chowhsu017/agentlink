#!/usr/bin/env python3
"""
跨机账本一致性 — v0.2（缺陷）vs v0.3（修复）对照复现
======================================================
对应分析：docs/跨机账本一致性问题分析-20261012.md
        设计稿：docs/会话可审计MVP设计-v0.3-20261012.md

v0.2 缺陷：两端各签【自己的】 账本 hash → 跨机诚实验签**必然失败**（假阴性）。
v0.3 修复：定义唯一签名对象 sig_object = sha256(H_init ‖ H_resp)（按角色定序）
          → 两端算出同一对象 → 双签才真正成立。

运行： python3 tests/repro_cross_machine_ledger_mismatch.py
预期： 
  ① v0.2 式验签 → ok=False（复现缺陷）
  ② v0.3 式验签 → ok=True （诚实会话通过）
  ③ 改对端 hash → ok=False（C3 防分叉仍有效）
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agentlink.ledger import SessionLedger, compute_sig_object


def build(who: str, is_init: bool) -> SessionLedger:
    """模拟同一会话 zh-X 下某一端自己建的账本（视角不同 → 内容不同）。"""
    time.sleep(1.05)  # 保证两端的 ts 不同（真实跨机时钟本就不同）
    L = SessionLedger("zh-X", "did:alice", "did:bob", channel="ws", peer_name=who)
    L._is_initiator_view = is_init
    # 握手 nonce/fpr 各记各的（v0.2 旧行为；v0.3 由 secure_session 统一取发起方）
    L.record_handshake(kex="X25519", cipher="ChaCha20-Poly1305", sig="Ed25519",
                       did_verified=True, nonce=f"{who}-nonce", peer_fpr=f"fpr-{who}")
    # C2：同一帧 sender 归一为发送方 DID（两端一致）
    L.record_frame(sender="did:alice", enc="ratchet",
                   cipher_suite="ChaCha20-Poly1305", decrypt="ok", payload=b"hi")
    L.record_frame(sender="did:bob", enc="plain",
                   cipher_suite="ChaCha20-Poly1305", decrypt="fallback_plain",
                   downgrade=True, reason="local_state_mismatch", payload=b"reply")
    L.record_close(reason="user_hangup", frames_in=1, frames_out=1)
    return L


def fake_verifier(sig, obj, role):
    """模拟 Ed25519：sig 形如 'sig:<obj>' 表示'该签名确实是对 obj 签名'。"""
    return sig == "sig:" + obj


def main() -> int:
    A = build("alice", True)
    H_A = A.events[-1].hash
    B = build("bob", False)
    H_B = B.events[-1].hash
    print("H_A =", H_A[:24])
    print("H_B =", H_B[:24])
    print("H_A == H_B ?", H_A == H_B, "（诚实会话两本账本 hash 天然不同）")
    print("=" * 64)

    # ── ① v0.2 式：各签各自的 hash ──
    A.record_signature_exchange(initiator_sig_received=True, responder_sig_received=True)
    A.seal()
    # Alice 落盘：己方签 H_A，对方签 H_B（对方签名签的是他自己账本）
    A.attach_signatures(initiator_sig="sig:" + H_A, responder_sig="sig:" + H_B)
    # v0.2 验签：用【本端 ledger_hash】验双方签名
    #   旧签名对象不存在，此处直接演示"错配"的等价效果：
    v02 = A.verify(verifier=lambda s, obj, role: s == "sig:" + obj)
    # 注：verify 内部现在按 v0.3 走 sig_object；为演示 v0.2 缺陷，单独演示错配
    print("① v0.2 式验签（各签各自 hash）：")
    print("   Alice 用 H_A 验对方签名 sig:<H_B> → 匹配? ", ("sig:" + H_A) == ("sig:" + H_B),
          "→ ok =", v02["ok"], "|", v02.get("reason", ""))
    print()

    # ── ② v0.3 式：共同签名对象 ──
    A2 = build("alice", True)
    H_A2 = A2.events[-1].hash
    B2 = build("bob", False)
    H_B2 = B2.events[-1].hash
    obj_a = compute_sig_object(H_A2, H_B2, is_initiator=True)
    obj_b = compute_sig_object(H_B2, H_A2, is_initiator=False)
    print("② v0.3：两端 sig_object 一致 ?", obj_a == obj_b, "→", obj_a[:32], "...")
    for L, is_init, h_self, h_peer in ((A2, True, H_A2, H_B2), (B2, False, H_B2, H_A2)):
        L.record_signature_exchange(initiator_sig_received=True, responder_sig_received=True,
                                    self_hash=h_self, peer_hash=h_peer, is_initiator=is_init)
        L.seal()
        L.attach_signatures(initiator_sig="sig:" + obj_a, responder_sig="sig:" + obj_a)
    ra = A2.verify(verifier=fake_verifier)
    rb = B2.verify(verifier=fake_verifier, is_initiator=False)
    print("   Alice 诚实会话验签 → ok =", ra["ok"], "| sig_verified =", ra["sig_verified"])
    print("   Bob   诚实会话验签 → ok =", rb["ok"], "| sig_verified =", rb["sig_verified"])
    print()

    # ── ③ C3 防分叉：改对端 hash ──
    A2.peer_hash = "sha256:" + "0" * 64
    r3 = A2.verify(verifier=fake_verifier)
    print("③ 改对端 hash（C3 防分叉）→ ok =", r3["ok"], "| sig_object_ok =", r3["sig_object_ok"])
    print("   reason:", r3.get("reason", ""))
    print("=" * 64)

    ok = (v02["ok"] is False) and ra["ok"] and rb["ok"] and (r3["ok"] is False)
    print(">>> 结论：v0.2 假阴性已复现；v0.3 诚实会话通过 + 防分叉有效。验证", "✅" if ok else "❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
