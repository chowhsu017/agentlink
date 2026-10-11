# AgentLink 会话可审计 MVP 设计 v0.3

> 版本：v0.3（修订稿）｜ 日期：2026-10-12
> 上游：v0.2（`docs/会话可审计MVP设计-v0.2-20261011.md`，主链路已接通、40 测试全过）
> 修订依据：`docs/跨机账本一致性问题分析-20261012.md`（真机回归暴露的结构性问题）
> 决策：**D1=B（双本拼接签名对象）｜ D2=做（附带规范三字段）｜ D3=缓（IPv6/IPv4 单列）**
> **本版只修"跨机账本一致性"，不动 MVP 边界，不纳入 P1/P2。**

---

## 〇、v0.3 变更摘要（先看这个）

| 编号 | 问题 | v0.3 改动 | 影响面 |
|:--|:--|:--|:--|
| **C1（D1=B）** | 两端各签各自的 hash → 对方签名签的是**对方账本** → 诚实会话双签校验**必然失败**（假阴性） | 签名对象改为 **`H(my_hash ‖ peer_hash)`**（角色定序）；交换时**保留并使用**对方 `ledger_hash` 字段 | `ledger.py` 签名/验签 + `node.py` 交换 |
| **C2（D2）** | 两本账本字段天然不同（`initiator/responder` 占位、`direction` 视角词、握手 nonce/fpr 各记各的）→ 认知负担大、未来任何对账都难 | **规范三字段**：①`initiator/responder` 协商时双方写死 ②`direction` 归一到**发送方 DID** ③握手 `nonce/fpr` 统一取**发起方**视角 | 数据结构 + 建账本 + 每帧记录 |
| **C3** | 设计 §3.4.3「防分叉」是纸面条款（对方 hash 收到即弃） | C1 的拼接对象**天然覆盖**防分叉：改任一端 hash → 对象变 → 签名验不过 | 随 C1 解决，不额外加机制 |

> **一句话**：v0.2 把"钢筋"（双签交换）补上了，但**两头钢筋没焊在一起**——
> 各签各的 hash，跨机一验就断。v0.3 只做一件事：**让双方签同一个对象**。

---

## 一、问题背景（详见分析稿，此处压缩）

### 1.1 现场（代码级）

- `secure_session._start_ledger()` 每端各起**一本**账本（`secure_session.py:125`）。
- 两本账本在 `initiator/responder/started_at/ts/direction/nonce/fpr/close.reason/帧数` 上**必然不同**。
- 哈希链把上述全量字段纳入输入 → `H_A ≠ H_B` 几乎必然（实测复现：`4ce26bd9… ≠ cc1262a7…`）。
- `node._finalize_ledger()` 每端签**自己的** `pre_hash`，交换时对方 `ledger_hash` 字段**收到即弃**（`node.py:469`）。
- 验签：`verifier(对端签名, 本端 ledger_hash, ...)` → 用 `H_A` 验 `sign(B,H_B)` → **必然失败**。

### 1.2 定性

**诚实会话被判 tampered（假阴性）**——比"不验签"更糟：制造假警报，让篡改检测信用归零（狼来了），并持续产 `critical` 告警触发疲劳。

### 1.3 v0.2 裁决衔接

v0.2 采纳了 Kimi 的 H1/H3/H4。**v0.3 暴露的是 v0.2 实现 H1 时漏掉的一环**：
H1 要求"双签"，但**没定义唯一的签名对象**。两份独立账本 = 两个对象 → 双签机制不成立。
本版补齐这个定义。

---

## 二、v0.3 核心设计：双本拼接签名对象（C1）

### 2.1 签名对象定义

```
role-order:  initiator 在前，responder 在后（与会话角色绑定，非本地视角）

sig_object = sha256( H_initiator_view ‖ H_responder_view )
             其中 ‖ 为字节拼接，两个 H 均为各自账本哈希链的链尾 hash（64 hex 字符）
```

- **发起方（Alice）**：`H_initiator_view = H_A`，`H_responder_view = H_B`（交换时从对端拿到）
- **响应方（Bob）**：`H_initiator_view = H_A`（交换时从对端拿到），`H_responder_view = H_B`
- **两端算出同一个 `sig_object`** ✅

### 2.2 交换协议（修订 §3.4）

```
会话结束（hangup）
  ├─ record_close()
  ├─ H_self = 本端链尾 hash
  ├─ WS 发送 {type:"ledger_sig", ledger_hash:H_self, sig:?}     ← 先只发 hash
  ├─ 收对方 {ledger_hash:H_peer}
  ├─ sig_object = sha256( θ(H_self,H_peer) )                    ← 按角色定序
  ├─ my_sig = Ed25519_sign(私钥, sig_object)
  ├─ WS 发送 {type:"ledger_sig", sig:my_sig}                    ← 发签名
  ├─ 收对方 sig
  ├─ record_signature_exchange(sig_object, both_sigs_received)
  ├─ ledger_hash = seal()                                       ← 本端账本 hash（不变）
  ├─ attach_signatures(initiator_sig, responder_sig)            ← 双方对 sig_object 的签名
  └─ save() → <sid>.jsonl + <sid>.sig（含 sig_object）
```

> ⚠️ **两轮交换**：先换 hash，再换签名（因为签名对象依赖双方 hash）。
> 也可一轮：消息里同时带 `ledger_hash` + `sig`，但签名对象需**等收到对方 hash 才可算**——
> 故采用"先发 hash，收到对方 hash 后算对象再发 sig"的两轮式。超时策略沿用 v0.2（3s 超时即降级为单签，审计不挂死会话）。

### 2.3 验签规则（修订）

```python
verify(sig_object=?, verifier=...) →
  # 1) 重算本端哈希链 → 得 H_self
  # 2) 从 <sid>.sig 读回 sig_object + 对方 ledger_hash
  # 3) 重算 sig_object' = sha256(θ(H_self, H_peer_from_sigfile))
  # 4) 若 sig_object' != sig_object  → tampered（本端或对端 hash 被改）
  # 5) 用 sig_object 验双方签名
```

**这一步同时落地防分叉（C3）**：
- 改本端账本 → `H_self` 变 → `sig_object'` 变 → 验不过
- 改 sig 文件里记录的对端 hash → `sig_object'` 变 → 验不过
→ **任一端的 hash 被动手脚，都能独立发现**（不再依赖"两 hash 相等"这个不成立的假设）。

### 2.4 新增/变更字段

```json
{
  "ledger_version": "1.2",
  "signature_exchange": {
    "sig_object": "sha256:...",          // 新增：双方共同签名对象
    "self_hash": "sha256:...",           // 本端链尾 hash
    "peer_hash_received": "sha256:...",  // 新增：对端链尾 hash（不再是死字段）
    "role_order": "initiator_first",     // 定序规则（便于复算）
    "both_sigs_received": true
  },
  "signatures": {
    "initiator": "ed25519:...",          // 对 sig_object 签名
    "responder": "ed25519:...",
    "verified_both": null
  }
}
```

> `<sid>.sig` 文件结构同步增 `sig_object` / `peer_hash` / `self_hash` / `role_order`。

---

## 三、规范三字段（C2）

### 3.1 `initiator` / `responder`：协商时双方写死

**问题**：`secure_session.py:139` `initiator` 取"对端 DID 或占位"（注释"调用方后补"）→ 响应方建的账本 `initiator/responder` 语义**可能整体反了**。

**修法**：会话协商（call/ring）阶段即确定 `initiator_did` / `responder_did`，**两端写同一套**：

```
initiator = 发起方 DID（= call 消息 sender_did）
responder = 响应方 DID（= ring 消息的应答方 DID）
```

响应方建账本时，`initiator` 必须写**对端（发起方）DID**，`responder` 写**自己 DID**——与发起方一致。

### 3.2 `direction`：归一到发送方 DID

**问题**：`direction` 记 `in/out`（视角词），两端相反，直接进哈希输入。

**修法**：改为记**发送方 DID**（或 `self`/`peer` 的角色无关词）：

```
"direction": "self"  → 本端发出（对端视角就是 peer）
# 或
"sender_did": "did:agentlink:node-a:..."
```

两端对"同一帧"记为同一值 → 哈希可对齐。

### 3.3 握手 `nonce` / `fpr`：统一取发起方视角

**问题**：两端各记自己那侧的 nonce/fpr，进哈希输入 → 不同。

**修法**：**两侧都记【发起方】产生的 nonce 与【发起方视角】的 peer_fpr**：

```
did_challenge_nonce : 发起方产生的 nonce（两侧一致）
peer_pubkey_fpr     : 发起方视角看到的对端 key 指纹（两侧一致）
```

（H6 轻量预防的初衷不变，只是**统一到同一视角**。）

> ⚠️ **`ts` 不规范化**（保留本地时钟）。理由：跨机时钟差是物理事实，强行统一会引入新欺骗面；
> 时钟问题由 v0.2 已做的"`seq` 纳入哈希链"缓解（乱序/重排暴露），v0.3 不扩大战线。

---

## 四、接入点变更（相对 v0.2）

| 接入点 | 文件 | v0.2 | v0.3 变化 |
|:--|:--|:--|:--|
| ① 会话建立 | `secure_session.py` | 起账本 + handshake | **采用规范标量**（initiator/responder 写死、nonce/fpr 取发起方） |
| ② 每帧解密 | `secure_session.py` | 全量 frame + 分级 | **`direction` 改发送方 DID** |
| ③ 会话关闭 | `node.py` | 单轮交换签名（签本端 hash） | **两轮交换 hash→签名，签 `sig_object`** |
| ④ 签名交换 | `ledger.py` | `attach_signatures` | **新增 `compute_sig_object()` + 保留 peer_hash** |
| ⑤ 账本存储 | `ledger.py` | `<sid>.jsonl` + `.sig` | **`.sig` 增 sig_object/peer_hash/self_hash** |
| ⑥ 查询接口 | `cli.py` | `verify` 双签 | **verify 改验 `sig_object`** |

**改动量估计**：`ledger.py` +~80 行（含 compute_sig_object/verify 重写）｜`node.py` ~15 行（两轮交换）｜`secure_session.py` ~10 行（规范字段）｜`cli.py` ~5 行｜新增/改测试 ~4 条。

---

## 五、验证方案（v0.3）

```
验证 A（修假阴性）：诚实跨机会话
  · 双端均 v0.3，跑正常 @search
  · 断言 sig_object 两端一致
  · 断言 verify() == ok=True 且 sig_verified=True      ← 核心：v0.2 此处必然 False
验证 B（防篡改仍有效）：单方改本端账本重签
  · 删改中间事件 → 重算本端链 → H_self 变
  · 断言 verify() == False（sig_object' ≠ sig_object）
验证 C（防分叉落地）：单独改 <sid>.sig 里的 peer_hash
  · 断言 verify() == False（不再"收到即弃"）
验证 D（规范字段）：两端账本的对应字段值一致
  · initiator/responder 一致；同一帧 direction/sender 一致；握手 nonce/fpr 一致
验证 E（回归）：v0.2 的 40 项测试 + 篡改检测仍全过
```

**成功判据**：**验证 A 通过 = "跨机双签"从假阴性变成真有效**（这是 v0.3 相对 v0.2 的核心提升）。

**诚实边界**：验证 A 需**对端同步升级到 v0.3** 才能跑真机；
升级前先跑本机"双实例模拟"（复现脚本 `tests/repro_cross_machine_ledger_mismatch.py` 的反向版：改造成"应通过"断言）。

---

## 六、风险与坦白（承接 v0.2）

| 风险 | v0.2 状态 | v0.3 状态 |
|:--|:--|:--|
| 跨机双签假阴性 | 🔴 未发现 | ✅ **本版修复（C1）** |
| 防分叉纸面化 | 🔴 未实现 | ✅ **本版落地（C3）** |
| 账本字段两端不一致 | 🟠 未处理 | ✅ **规范三字段（C2）** |
| 降级误报/漏报 | ⚠️ 部分解决（H3） | ⚠️ 维持（正交，不扩大） |
| 私钥泄露 | ❌ 未解决 | ❌ 未解决（超 MVP） |
| 交换信道被劫持 | ❌ 未解决 | ❌ 未解决（属通联层） |
| 被审计代码自报 | ⚠️ 根本局限 | ⚠️ 维持（需独立见证，P2） |
| 时钟漂移 | ✅ seq 纳入链 | ✅ 维持 + `ts` 不强规范（见 §3.3） |

> **诚实标注**：v0.3 只修"跨机账本一致性"这一件事。
> **不解决**：私钥泄露、信道劫持、被审计代码自报（P2）、增量验证/Merkle（P1）。

---

## 七、下一步

1. **评审 v0.3**（本稿）→ 重点确认 §2.2 两轮交换时序 + §2.1 定序规则
2. 落地顺序：`ledger.py`（compute_sig_object + verify 重写）→ `node.py`（两轮交换）→ `secure_session.py`（规范字段）→ `cli.py` → 5 条验证
3. **D3 单列待办**：IPv6/IPv4 WS 不兼容（`_force_ipv4`）——属通联层，单独排期
4. **P1/P2 暂缓**：Merkle/外部锚定/meta-audit/replay/独立见证——按既定判断维持暂缓

---

## 附：v0.2 → v0.3 逐条对照

| 编号 | 议题 | v0.2 | v0.3 | 采纳 |
|:--|:--|:--|:--|:--|
| **C1** | 签名对象唯一 | ❌ 各签各自 hash | ✅ 双本拼接 `H(A‖B)` | ✅ 本版核心 |
| **C2** | 规范三字段 | ❌ 两端各记各的 | ✅ initiator/direction/nonce 规范化 | ✅ 本版 |
| **C3** | 防分叉 | ❌ 纸面条款 | ✅ 拼接对象天然覆盖 | ✅ 随 C1 |
| C4 | IPv6/IPv4 WS | ❌ 未发现 | ⏸️ 单列待办 | ❌ 本版不做 |
| （H1/H3/H4） | v0.2 已采纳三条 | ✅ 已实现 | ✅ 维持 | — |
| （H2/H5/H6/P2） | — | ⏸️ 暂缓 | ⏸️ 维持暂缓 | — |

---

**相关文件：**
- 问题分析：`docs/跨机账本一致性问题分析-20261012.md`
- 复现脚本：`tests/repro_cross_machine_ledger_mismatch.py`
- v0.2 设计：`docs/会话可审计MVP设计-v0.2-20261011.md`
- v0.2 报告：`docs/会话账本-v0.2接入完成报告-20261011.md`
- 核心代码：`agentlink/ledger.py` / `agentlink/node.py:338` / `agentlink/secure_session.py:125`
