"""
AgentLink 会话账本（Session Ledger）— v0.3 实现
=====================================================

对应设计稿：docs/会话可审计MVP设计-v0.3-20261012.md
          （问题分析：docs/跨机账本一致性问题分析-20261012.md）
定位：**纯存储模块，无网络依赖**。签名交换的信道动作留在 node.py。

职责边界（重要）：
  ✅ 本模块负责：事件记录 / 降级分级 / 哈希链 / 签名对象计算 / 双签校验 / 落盘 / 只读查询
  ❌ 本模块**不负责**：发起 WS 通信、交换签名（那要复用信道 → 归 node.py）

演进脉络（勿删，理解设计的关键）：
  v0.2：H1 签名交换 / H3 降级分级 / H4 全量记录
  v0.3：**C1 双本拼接签名对象 / C2 规范三字段 / C3 防分叉**

v0.3 核心（为什么改）：
  v0.2 让两端各建一本账本、各签【自己的】 hash → 跨机诚实验签**必然失败**（假阴性）。
  v0.3 定义**唯一签名对象**：sig_object = sha256(H_initiator_view ‖ H_responder_view)
  （按会话角色定序，非本地视角）→ 两端算出同一对象 → 双签才真正成立。

用法：
    from agentlink.ledger import SessionLedger, classify_downgrade, compute_sig_object

    ledger = SessionLedger(session_id, initiator_did, responder_did, channel="ws")
    ledger.record_handshake(kex=..., cipher=..., did_verified=True, nonce=..., peer_fpr=...)
    ledger.record_frame(sender="self", enc="plain", cipher_suite=..., decrypt="fallback_plain",
                        downgrade=True, reason="local_state_mismatch", payload=b"...")
    ledger.record_close(reason="ws_disconnect", frames_in=1, frames_out=0)
    # ... 会话结束后，node.py 交换「本端 hash + 对方 hash」，再交换签名
    ledger.record_signature_exchange(self_hash=H_self, peer_hash=H_peer,
                                     initiator_sig_received=True, responder_sig_received=True)
    ledger.seal()                       # 算 ledger_hash + 封存
    ledger.attach_signatures(initiator_sig=..., responder_sig=...)  # 均对 sig_object 签
    ledger.save()                       # 落盘 <sid>.jsonl + <sid>.sig
    result = ledger.verify()            # 双签校验（对 sig_object）
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

LEDGER_VERSION = "1.2"
DEFAULT_LEDGER_DIR = os.path.expanduser("~/.agentlink/ledgers")

# v0.3 C1：签名对象的定序规则（与会话角色绑定，非本地视角）
SIG_OBJECT_ROLE_ORDER = "initiator_first"

# H3：降级原因 → 分级 映射表
# noise     = 大概率正常（本地状态/乱序）
# suspicious= 需关注（密档突变/连续降级）
# critical  = 疑似攻击（跌至明文/签名失败）
DOWNGRADE_CLASS_MAP = {
    "local_state_mismatch": "noise",
    "reordered_frame": "noise",
    "unexpected_cipher_change": "suspicious",
    "ratchet_desync_prolonged": "suspicious",
    "plaintext_downgrade": "critical",
    "signature_verify_failed": "critical",
}


def classify_downgrade(reason: str) -> str:
    """
    H3 核心：把降级原因映射到三级分类。
    未登记的原因一律保守归为 suspicious（未知≠安全）。
    """
    return DOWNGRADE_CLASS_MAP.get(reason, "suspicious")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_sig_object(h_self: str, h_peer: str, *, is_initiator: bool) -> str:
    """
    v0.3 C1 核心：计算**双方共同的签名对象**。

    规则：sig_object = sha256( H_initiator_view ‖ H_responder_view )
      · 定序**按会话角色**（initiator 在前），不按本地视角
      · is_initiator=True  → 本端是发起方 → (h_self, h_peer)
      · is_initiator=False → 本端是响应方 → (h_peer, h_self)
    两端对同一会话算出同一 sig_object。

    返回："sha256:<hex>" 形式的字符串（与 payload_sha256 风格统一）。
    """
    if is_initiator:
        h_i, h_r = h_self, h_peer
    else:
        h_i, h_r = h_peer, h_self
    payload = (h_i + "|" + h_r).encode("utf-8")
    return "sha256:" + _sha256_hex(payload)


def _canonical_json(obj) -> bytes:
    """规范化 JSON（key 排序、无空白）→ 保证哈希可复现。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


# ---------------------------------------------------------------------------
# 事件结构
# ---------------------------------------------------------------------------

@dataclass
class LedgerEvent:
    seq: int
    ts: str
    type: str                    # handshake / frame / close / signature_exchange
    detail: dict
    hash: Optional[str] = None   # 哈希链：H(prev_hash ‖ seq ‖ event)
    hash_exempt: bool = False    # True = 不参与哈希链（如 signature_exchange，它携带签名本身）

    def to_dict(self) -> dict:
        d = {"seq": self.seq, "ts": self.ts, "type": self.type, "detail": self.detail}
        if self.hash:
            d["hash"] = self.hash
        return d

    def _hash_input(self) -> dict:
        """哈希链的输入 = 不含 hash 字段本身的事件内容（防自引用）。"""
        return {"seq": self.seq, "ts": self.ts, "type": self.type, "detail": self.detail}


# ---------------------------------------------------------------------------
# 会话账本
# ---------------------------------------------------------------------------

@dataclass
class SessionLedger:
    session_id: str
    initiator: str               # initiator DID
    responder: str               # responder DID
    channel: str = "ws"
    started_at: str = field(default_factory=_now_iso)
    peer_name: str = ""          # 我方在本会话中的名字（node-a / node-b）
    ledger_dir: str = DEFAULT_LEDGER_DIR

    events: list = field(default_factory=list)
    downgrade_count: int = 0
    downgrade_count_by_class: dict = field(default_factory=lambda: {"noise": 0, "suspicious": 0, "critical": 0})

    ledger_hash: Optional[str] = None
    signatures: dict = field(default_factory=dict)   # {"initiator":..., "responder":...}（均对 sig_object 签）
    verified_both: Optional[bool] = None

    # v0.3 C1：签名交换元数据
    sig_object: Optional[str] = None      # 双方共同签名对象
    self_hash: Optional[str] = None       # 本端链尾 hash
    peer_hash: Optional[str] = None       # 对端链尾 hash（v0.2 收到即弃，v0.3 保留并校验）

    _sealed: bool = False
    _last_hash: str = ""
    _is_initiator_view: bool = True   # v0.3 C1：本端角色（用于 sig_object 定序）；True=发起方

    # ---- 内部：追加事件并接上哈希链 ----
    def _append(self, etype: str, detail: dict, hash_exempt: bool = False) -> LedgerEvent:
        if self._sealed:
            raise RuntimeError(f"ledger {self.session_id} already sealed; cannot append")
        seq = len(self.events)
        ev = LedgerEvent(seq=seq, ts=_now_iso(), type=etype, detail=detail, hash_exempt=hash_exempt)
        if hash_exempt:
            # 不参与哈希链：hash 标为 None，prev 不变
            ev.hash = None
            self.events.append(ev)
            return ev
        # 哈希链：H(prev_hash ‖ seq ‖ event_canonical)  ← 输入**不含** hash 字段本身
        payload = (self._last_hash + "|" + str(seq) + "|" + _canonical_json(ev._hash_input()).decode("utf-8"))
        ev.hash = _sha256_hex(payload.encode("utf-8"))
        self._last_hash = ev.hash
        self.events.append(ev)
        return ev

    # ---- ① 握手 ----
    def record_handshake(self, *, kex: str, cipher: str, sig: str,
                         did_verified: bool, nonce: str = "", peer_fpr: str = "") -> LedgerEvent:
        return self._append("handshake", {
            "kex": kex, "cipher": cipher, "sig": sig,
            "did_verified": did_verified,
            "did_challenge_nonce": nonce,        # H6 轻量：便于事后复核 DID 验证
            "peer_pubkey_fpr": peer_fpr,         # H6 轻量
        })

    # ---- ② 帧（H4：全量记录；H3：分级；v0.3 C2：direction 归一到发送方）----
    def record_frame(self, *, enc: str, cipher_suite: str = "",
                     decrypt: str = "ok", downgrade: bool = False,
                     reason: str = "", payload: Optional[bytes] = None,
                     sender: str = "", direction: str = "") -> LedgerEvent:
        """
        **无条件调用**——正常帧、降级帧都记（H4）。
        payload 只记 sha256，不记本体（隐私 + 体积平衡）。

        v0.3 C2：方向字段规范化。
          · sender 应传**发送方 DID**（绝对值，两端对同一帧一致）
          · 亦接受 "self"/"peer"（本地相对），但仅作单机用；跨机对齐请用 DID
          · 兼容旧 direction："in" / "out"（仅在 sender 未给时回落，已不推荐）
        """
        # C2 规范化：sender 优先；否则由 direction 推导（in→peer, out→self）
        if not sender:
            sender = {"in": "peer", "out": "self"}.get(direction, "")
        detail = {
            "sender": sender,                # v0.3 C2：发送方 DID（推荐）或 "self"/"peer"
            "enc": enc,                      # "ratchet" / "plain"
            "cipher_suite": cipher_suite,    # H3 独立密档字段（冗余兜底）
            "decrypt": decrypt,              # "ok" / "fallback_plain"
            "downgrade": bool(downgrade),
        }
        if payload is not None:
            detail["payload_sha256"] = "sha256:" + _sha256_hex(payload)
        if downgrade:
            cls = classify_downgrade(reason)
            detail["downgrade_class"] = cls
            detail["downgrade_reason"] = reason
            self.downgrade_count += 1
            self.downgrade_count_by_class[cls] = self.downgrade_count_by_class.get(cls, 0) + 1
        return self._append("frame", detail)

    # ---- ③ 关闭 ----
    def record_close(self, *, reason: str, frames_in: int = 0, frames_out: int = 0) -> LedgerEvent:
        return self._append("close", {
            "reason": reason, "frames_in": frames_in, "frames_out": frames_out,
        })

    # ---- ④ 签名交换事件（H1+v0.3 C1：由 node.py 交换完成后回调）----
    def record_signature_exchange(self, *, initiator_sig_received: bool,
                                  responder_sig_received: bool,
                                  self_hash: str = "", peer_hash: str = "",
                                  sig_object: str = "", is_initiator: bool = True) -> LedgerEvent:
        """
        v0.3 C1：除记录被收双方签名，还记录 **本端/对端账本 hash** 与 **共同签名对象**。
        hash_exempt=True：本事件携带签名/hash 元数据，不纳入哈希链，
        以保证「双方签名对象」= 交换前的链尾 hash（= 最终 ledger_hash 参与链部分）。
        """
        # 允许调用方直接传 sig_object；否则由双 hash 推
        if not sig_object and self_hash and peer_hash:
            sig_object = compute_sig_object(self_hash, peer_hash, is_initiator=is_initiator)
        if self_hash:
            self.self_hash = self_hash
        if peer_hash:
            self.peer_hash = peer_hash
        if sig_object:
            self.sig_object = sig_object
        return self._append("signature_exchange", {
            "initiator_sig_received": initiator_sig_received,
            "responder_sig_received": responder_sig_received,
            "sig_object": sig_object or self.sig_object or "",
            "self_hash": self_hash or self.self_hash or "",
            "peer_hash": peer_hash or self.peer_hash or "",
            "role_order": SIG_OBJECT_ROLE_ORDER,
        }, hash_exempt=True)

    # ---- H1：接入双方签名 ----
    def attach_signatures(self, *, initiator_sig: str, responder_sig: str):
        """
        node.py 完成签名交换后调用，把【双方签名】塞进账本。
        注意：b64/hex 字符串，不是对象。
        """
        self.signatures = {"initiator": initiator_sig, "responder": responder_sig}

    # ---- 封账本 ----
    def seal(self) -> str:
        if not self.events:
            raise RuntimeError("empty ledger")
        # 最终 hash = 最后一个**参与哈希链**的事件的 hash
        chained = [e for e in self.events if not getattr(e, "hash_exempt", False) and e.hash]
        self.ledger_hash = chained[-1].hash if chained else None
        self._sealed = True
        return self.ledger_hash

    # ---- 序列化 ----
    def to_dict(self) -> dict:
        return {
            "ledger_version": LEDGER_VERSION,
            "session_id": self.session_id,
            "initiator": self.initiator,
            "responder": self.responder,
            "channel": self.channel,
            "started_at": self.started_at,
            "events": [e.to_dict() for e in self.events],
            "downgrade_count": self.downgrade_count,
            "downgrade_count_by_class": self.downgrade_count_by_class,
            "ledger_hash": self.ledger_hash,
            "signatures": self.signatures,
            "verified_both": self.verified_both,
            "sig_object": self.sig_object,
            "self_hash": self.self_hash,
            "peer_hash": self.peer_hash,
        }

    # ---- 落盘：<sid>.jsonl + <sid>.sig ----
    def save(self) -> tuple[str, str]:
        os.makedirs(self.ledger_dir, exist_ok=True)
        jsonl_path = os.path.join(self.ledger_dir, f"{self.session_id}.jsonl")
        sig_path = os.path.join(self.ledger_dir, f"{self.session_id}.sig")
        # 账本本体一行一条事件（append-only 语义，实际整本重写以保封存一致性）
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for e in self.events:
                f.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")
            f.write(json.dumps({
                "_meta": True,
                "ledger_version": LEDGER_VERSION,
                "session_id": self.session_id,
                "initiator": self.initiator,
                "responder": self.responder,
                "channel": self.channel,
                "started_at": self.started_at,
                "downgrade_count": self.downgrade_count,
                "downgrade_count_by_class": self.downgrade_count_by_class,
                "ledger_hash": self.ledger_hash,
            }, ensure_ascii=False) + "\n")
        # 签名独立落盘（H1+v0.3 C1：对方签名必须持久化，作为独立存证）
        with open(sig_path, "w", encoding="utf-8") as f:
            json.dump({
                "session_id": self.session_id,
                "ledger_hash": self.ledger_hash,
                "sig_object": self.sig_object,          # v0.3：双方共同签名对象
                "self_hash": self.self_hash,            # v0.3：本端链尾 hash
                "peer_hash": self.peer_hash,            # v0.3：对端链尾 hash
                "role_order": SIG_OBJECT_ROLE_ORDER,
                "signatures": self.signatures,
            }, f, ensure_ascii=False, indent=2)
        return jsonl_path, sig_path

    # ---- 双签校验（H1 核心 + v0.3 C1/C3）----
    def verify(self, *, verifier=None, require_peer_sig: bool = True,
               is_initiator: bool = True) -> dict:
        """
        校验规则：
          1. 重算哈希链，确认 events 未被删改
          2. 检查 ledger_hash 与末事件 hash 一致
          3. H1：检查**双方**签名齐备（缺对方签名 → invalid）
          4. v0.3 C1/C3：重算 sig_object' = sha256(θ(本端 hash, 对端 hash))
             并与记录的 sig_object 比对 —— 任一 hash 被改 → 对象变 → 暴露
          5. 若提供 verifier(签名, sig_object, 角色) 回调 → 对 **sig_object** 实际验签

        verifier 形如: verifier(sig_str, sig_object, role) -> bool
        返回 dict(ok, hash_chain_ok, ledger_hash_ok, both_sigs_present,
                  sig_object_ok, sig_verified, reason)
        """
        out = {
            "ok": False, "hash_chain_ok": False, "ledger_hash_ok": False,
            "both_sigs_present": False, "sig_object_ok": None,
            "sig_verified": None, "reason": "",
        }
        # 1) 重算哈希链（跳过 hash_exempt 事件）
        prev = ""
        for e in self.events:
            if getattr(e, "hash_exempt", False):
                continue
            payload = (prev + "|" + str(e.seq) + "|" + _canonical_json(e._hash_input()).decode("utf-8"))
            calc = _sha256_hex(payload.encode("utf-8"))
            if calc != e.hash:
                out["reason"] = f"hash chain broken at seq={e.seq}"
                return out
            prev = e.hash
        out["hash_chain_ok"] = True
        # 2) ledger_hash
        chained = [e for e in self.events if not getattr(e, "hash_exempt", False) and e.hash]
        expected = chained[-1].hash if chained else None
        if self.ledger_hash != expected:
            out["reason"] = "ledger_hash mismatch"
            return out
        out["ledger_hash_ok"] = True
        # 3) H1：双签齐备
        have_i = bool(self.signatures.get("initiator"))
        have_r = bool(self.signatures.get("responder"))
        out["both_sigs_present"] = have_i and have_r
        if require_peer_sig and not out["both_sigs_present"]:
            out["reason"] = "missing signature(s): 单方出示无效（H1）"
            return out
        # 4) v0.3 C3：重算 sig_object 并比对（防分叉 + 防单方改 hash）
        #    self_hash 应等于本端 ledger_hash；peer_hash 来自落盘记录（对方签名时锁定）
        self_hash_local = self.ledger_hash or ""
        peer_hash_local = self.peer_hash or ""
        if peer_hash_local:
            recomputed = compute_sig_object(self_hash_local, peer_hash_local,
                                            is_initiator=self._is_initiator_view)
            if not self.sig_object:
                out["reason"] = "sig_object missing (cannot verify cross-machine)"
                return out
            if recomputed != self.sig_object:
                out["sig_object_ok"] = False
                out["reason"] = "sig_object mismatch: 本端或对端账本 hash 被篡改（C3 防分叉）"
                return out
            out["sig_object_ok"] = True
        else:
            # 无私 hash（单签场景）—— sig_object 无法跨机校验，但不阻断本地链校验
            out["sig_object_ok"] = None
        # 5) 实际验签：对象 = sig_object
        if verifier is not None and out["both_sigs_present"]:
            target = self.sig_object or self.ledger_hash
            try:
                vi = verifier(self.signatures["initiator"], target, "initiator")
                vr = verifier(self.signatures["responder"], target, "responder")
                out["sig_verified"] = bool(vi and vr)
                if not out["sig_verified"]:
                    out["reason"] = "signature verification failed (tampered or wrong signer)"
                    return out
            except Exception as exc:  # noqa: BLE001
                out["reason"] = f"verifier error: {exc}"
                return out
        out["ok"] = True
        return out

    # ---- 只读加载 ----
    @staticmethod
    def load(session_id: str, ledger_dir: str = DEFAULT_LEDGER_DIR) -> "SessionLedger":
        jsonl_path = os.path.join(ledger_dir, f"{session_id}.jsonl")
        sig_path = os.path.join(ledger_dir, f"{session_id}.sig")
        with open(jsonl_path, "r", encoding="utf-8") as f:  # noqa: SIM115
            lines = [json.loads(x) for x in f if x.strip()]
        meta = next((x for x in lines if x.get("_meta")), {})
        evs = [x for x in lines if not x.get("_meta")]
        obj = SessionLedger(
            session_id=session_id,
            initiator=meta.get("initiator", ""),
            responder=meta.get("responder", ""),
            channel=meta.get("channel", "ws"),
            started_at=meta.get("started_at", ""),
            ledger_dir=ledger_dir,
        )
        obj.events = [LedgerEvent(seq=e["seq"], ts=e["ts"], type=e["type"],
                                  detail=e["detail"], hash=e.get("hash"),
                                  hash_exempt=(e.get("hash") is None and e["type"] == "signature_exchange"))
                      for e in evs]
        obj.downgrade_count = meta.get("downgrade_count", 0)
        obj.downgrade_count_by_class = meta.get("downgrade_count_by_class",
                                                 {"noise": 0, "suspicious": 0, "critical": 0})
        obj.ledger_hash = meta.get("ledger_hash")
        obj._sealed = True
        _chained = [e for e in obj.events if not getattr(e, "hash_exempt", False) and e.hash]
        obj._last_hash = _chained[-1].hash if _chained else ""
        if os.path.exists(sig_path):
            with open(sig_path, "r", encoding="utf-8") as f:
                sig = json.load(f)
            obj.signatures = sig.get("signatures", {})
            obj.sig_object = sig.get("sig_object")
            obj.self_hash = sig.get("self_hash")
            obj.peer_hash = sig.get("peer_hash")
        # 兼容：若 .sig 无 v0.3 字段，回落到 jsonl 的 signature_exchange 事件里取
        if not obj.sig_object or not obj.peer_hash:
            se = next((e for e in obj.events if e.type == "signature_exchange"), None)
            if se:
                obj.sig_object = obj.sig_object or se.detail.get("sig_object")
                obj.self_hash = obj.self_hash or se.detail.get("self_hash")
                obj.peer_hash = obj.peer_hash or se.detail.get("peer_hash")
        return obj


# ---------------------------------------------------------------------------
# 自测（python3 -m agentlink.ledger）
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    sid = "zh-selftest-0001"
    # 模拟双方各建一本账本（同一会话，视角不同）
    def build(is_init: bool):
        L = SessionLedger(sid,
                          "did:agentlink:node-a:AAA" if is_init else "did:agentlink:node-b:BBB",
                          "did:agentlink:node-b:BBB" if is_init else "did:agentlink:node-a:AAA")
        L._is_initiator_view = is_init
        L.record_handshake(kex="X25519", cipher="ChaCha20-Poly1305", sig="Ed25519",
                           did_verified=True, nonce="b3f2", peer_fpr="sha256:9a1c")
        L.record_frame(sender="self", enc="ratchet", cipher_suite="ChaCha20-Poly1305",
                       decrypt="ok", payload=b"normal frame")
        L.record_frame(sender="peer", enc="plain", cipher_suite="ChaCha20-Poly1305",
                       decrypt="fallback_plain", downgrade=True,
                       reason="local_state_mismatch", payload="@search 贪污".encode("utf-8"))
        L.record_close(reason="ws_disconnect", frames_in=1, frames_out=1)
        return L

    A = build(True)
    H_A = A.events[-1].hash
    B = build(False)
    H_B = B.events[-1].hash
    print("H_A =", H_A[:24], "...")
    print("H_B =", H_B[:24], "...")
    print("H_A == H_B ?", H_A == H_B, "  <- 诚实会话两本账本 hash 天然不同（v0.2 的坑）")

    # v0.3：双方算**同一个** sig_object
    sig_obj_a = compute_sig_object(H_A, H_B, is_initiator=True)
    sig_obj_b = compute_sig_object(H_B, H_A, is_initiator=False)
    print("sig_object 两端一致 ?", sig_obj_a == sig_obj_b, sig_obj_a[:28], "...")

    # 双方各自记签名（均对 sig_object 签）＋落盘
    for L, is_init, h_self, h_peer in ((A, True, H_A, H_B), (B, False, H_B, H_A)):
        L.record_signature_exchange(initiator_sig_received=True, responder_sig_received=True,
                                    self_hash=h_self, peer_hash=h_peer, is_initiator=is_init)
        L.seal()
        L.attach_signatures(initiator_sig="ed25519:I_SIG", responder_sig="ed25519:R_SIG")

    # 诚实双向验签：均应通过（v0.2 此处必然 False）
    ver = lambda s, obj, r: True
    print("A verify (诚实) =", A.verify(verifier=ver)  ["ok"])
    print("B verify (诚实) =", B.verify(verifier=ver, is_initiator=False)["ok"])

    # C3 防分叉：改对端 hash → sig_object 不匹配
    A.peer_hash = "sha256:" + "0" * 64
    print("A verify (被改 peer_hash) =", A.verify(verifier=ver))

    # 缺对方签名
    A.peer_hash = H_B
    A.signatures.pop("responder")
    print("verify(missing peer) =", A.verify())
