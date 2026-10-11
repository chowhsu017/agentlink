# AgentLink 社会层升级 — 会话可审计 MVP 设计 v0.2

> 版本：v0.2（修订稿）｜ 日期：2026-10-11
> 修订依据：Kimi 技术测评（`会话可审计MVP-Kimi测评-20261011.md`，总体评级 C+）
> **本版只改 P0 三条（H1/H3/H4），不动 MVP 边界、不纳入 P1/P2。**
> 上游现状：AgentLink v0.1.5（本地 = 上游 GitHub）
> v0.1 原稿：`会话可审计MVP设计-20261011.md`

---

## 〇、v0.2 变更摘要（先看这个）

| 编号 | 问题（Kimi 原话） | v0.2 改动 | 影响面 |
|:--|:--|:--|:--|
| **H1** | "单方改不了"是伪命题——签名不交换=没签 | 新增 **§3.4 签名交换协议**：会话结束强制双向交换并持久化对方签名；验签必须双签齐备 | 数据结构 + close 流程 |
| **H3** | downgrade 判定是被审计代码自报，分不清正常重传/乱序/真攻击 | 新增 **§3.2.1 降级原因分级**（三级）+ 独立记录密档字段 | 字段设计 + 判定逻辑 |
| **H4** | "只记异常帧"直接摧毁审计完整性 | **撤销"只记异常帧"**，改为全量记录 frame（仅 metadata，不记 payload），存储靠归档解决 | 记录策略 |

> **一句话**：v0.1 的骨架不动，把三根"关键韧带"接上——**签名要交换、降级要分级、帧要全记**。

---

## 一、问题背景（沿用 v0.1，不重复）

### 1.1 触发点：10-09 联机日志

```
📨 node-a [1] 收到: "🔒2EvQJMAuqpgPRZhK+c8vGlDyf+5+qdj1Ve9suVpbse8h56Meq7r7FOUR"
⚠️ node-a: 棘轮解密未命中，回退普通解密 [1]
🔓 node-a: 解密 [1] → "@search 贪污"
```

通信成功，但安全性掉档，**全程无记录**。这就是 Anthropic 报告「agent 没有记得它的同事」的最小复现。

### 1.2 定性：社会层问题（非通联层）

消息到了（通联 OK），但掉档无人记得（社会层缺失）。**"记得"是所有社会机制的地基。**

---

## 二、MVP 目标

**做：**
1. 每次会话生成结构化会话账本（session ledger）
2. 记录四类关键事件：握手 / 加密档位 / 降级 / 挂断
3. 账本用**双方 DID 签名封存 + 签名交换**（不可单方篡改）← **H1 强化**
4. 提供只读查询接口

**不做（明确划在 MVP 外）：**
- ❌ 实时告警 / UI
- ❌ 跨会话声誉聚合
- ❌ 仲裁协议
- ❌ 改传输层
- ❌ ~~只记异常帧~~（**v0.2 删除此项，见 H4**）

> **判据**：跑一次真实跨机会话，凭 session_id 查出账本，**明确写着**"是否降级、降几条、降级原因分级"。且任何一方单独出示的账本，**缺对方签名即判无效**。

---

## 三、数据结构设计（v0.2）

### 3.1 会话账本（结构）

```json
{
  "ledger_version": "1.1",
  "session_id": "zh-6e3553ba",
  "initiator": "did:agentlink:node-a:qMX70FdXri1uZSdy",
  "responder": "did:agentlink:node-b:Z1Rd+LemnMSJZT8/",
  "channel": "ws",
  "started_at": "2026-10-09T21:09:12+08:00",
  "events": [
    {
      "seq": 0,
      "ts": "2026-10-09T21:09:12+08:00",
      "type": "handshake",
      "detail": {
        "kex": "X25519",
        "cipher": "ChaCha20-Poly1305",
        "sig": "Ed25519",
        "did_verified": true,
        "did_challenge_nonce": "b3f2...",
        "peer_pubkey_fpr": "sha256:9a1c..."
      }
    },
    {
      "seq": 1,
      "ts": "2026-10-09T21:09:14+08:00",
      "type": "frame",
      "detail": {
        "direction": "in",
        "enc": "plain",
        "cipher_suite": "ChaCha20-Poly1305",
        "decrypt": "fallback_plain",
        "downgrade": true,
        "downgrade_class": "noise",
        "downgrade_reason": "local_state_mismatch",
        "payload_sha256": "sha256:7d3e..."
      }
    },
    {
      "seq": 2,
      "ts": "2026-10-09T21:10:03+08:00",
      "type": "close",
      "detail": { "reason": "ws_disconnect", "frames_in": 1, "frames_out": 0 }
    },
    {
      "seq": 3,
      "ts": "2026-10-09T21:10:04+08:00",
      "type": "signature_exchange",
      "detail": {
        "initiator_sig_received": true,
        "responder_sig_received": true
      }
    }
  ],
  "downgrade_count": 1,
  "downgrade_count_by_class": { "noise": 1, "suspicious": 0, "critical": 0 },
  "ledger_hash": "sha256:...",
  "signatures": {
    "initiator": "ed25519:...",
    "responder": "ed25519:...",
    "verified_both": true
  }
}
```

**v0.1 → v0.2 结构变化：**
- `ledger_version` 升 `1.1`
- `handshake.detail` 增 `did_challenge_nonce` + `peer_pubkey_fpr`（H6 的轻量预防，顺带做了，成本近乎零）
- `frame.detail` 增 `cipher_suite`（独立密档字段，H3）、`downgrade_class`（H3 分级）、`payload_sha256`（**不记 payload 本体，只记 hash**，平衡 H4 与隐私）
- 增 `downgrade_count_by_class`
- 增 `signature_exchange` 事件（H1）+ `signatures.verified_both`（H1）
- **所有 frame 全量记录**（H4），不设"只记异常帧"

### 3.2 四个必记字段（最小集，沿用）

| 字段 | 取值 | 意义 |
|:--|:--|:--|
| `type` | `handshake`/`frame`/`close`/`signature_exchange` | 事件类别 |
| `enc` | `ratchet`/`plain` | 本条加密档位 |
| `downgrade` | `true`/`false` | 是否降级（**告警位**） |
| `did_verified` | `true`/`false` | 对端身份是否验签 |

### 3.2.1 降级原因分级（H3 新增）

**核心问题**：棘轮未命中的原因可能是**正常重传 / 乱序 / 实现 bug / 真攻击**——v0.1 一律记 `ratchet_miss`，语义模糊，会造成误报或虚假安全感。

**v0.2 分三级 + 细分原因：**

| 分级 `downgrade_class` | 细分 `downgrade_reason` | 判定依据 | 含义 |
|:--|:--|:--|:--|
| `noise`（噪音） | `local_state_mismatch` | 本地棘轮状态与预期短暂不一致 | **大概率正常** |
| `noise` | `reordered_frame` | 帧 seq 与棘轮预期错位，但可自愈 | **大概率正常** |
| `suspicious`（可疑） | `unexpected_cipher_change` | `cipher_suite` 与握手协商值不符 | 需关注 |
| `suspicious` | `ratchet_desync_prolonged` | 连续 N 帧（默认 3）降级未恢复 | 需关注 |
| `critical`（严重） | `plaintext_downgrade` | 加密档位跌至明文且无合法理由 | **疑似攻击** |
| `critical` | `signature_verify_failed` | 对端签名验证失败 | **疑似攻击** |

**判定者**：仍由被审计代码判定（这是 Kimi H3 指出的内在局限，MVP 内无法完全消除），
**但 v0.2 通过两条补偿降低误判危害**：
1. **分级而非二元**——`noise` 别慌、`critical` 才响，避免告警疲劳
2. **独立密档字段 `cipher_suite`**——即使 `ratchet_miss` 被绕过（假阴性），专职复核仍可从"密档突变"独立发现异常

> ⚠️ **诚实标注**：被审计代码自报，理论上可被内存篡改/API hook 绕过。
> **MVP 不解决此根本问题**（需独立见证进程，属 P2）。v0.2 只做到"分级 + 冗余字段"，把危害降到"错误率可解释"。

### 3.3 防篡改：哈希链 + 双签（沿用 + 强化）

```
event[0].hash = H(session_id ‖ seq ‖ event[0])      ← seq 纳入输入（H5 轻量预防）
event[n].hash = H(event[n-1].hash ‖ seq ‖ event[n])  ← 哈希链
ledger_hash   = event[last].hash
```

**v0.2 强化点：**
- **`seq` 纳入 hash 链输入**——离线重排事件顺序 → seq 连续性断裂 → 篡改暴露（顺手覆盖 Kimi H5）
- 哈希链保证删/改中间一条 → 后续 hash 全断

### 3.4 🔴 签名交换协议（H1 新增，本版最关键）

> **Kimi 的判断**：v0.1 的"双签"如果不交换，就是**本地自嗨**——一方删改重签，本地照样验签通过。

#### 3.4.1 问题还原

```
❌ v0.1 做法（错误）：
Alice 签 ledger_hash → 存本地
Bob   签 ledger_hash → 存本地
→ 各存各的。Alice 删改账本、重算 hash、重签，本地验签仍通过
→ Bob 无从知晓。签名形同虚设。
```

#### 3.4.2 v0.2 正确做法：三步

```
① 会话结束时，双方各自计算 ledger_hash
② 通过现有 WS 信道，双向交换对 ledger_hash 的签名（seq=3 的 signature_exchange 事件）
③ 各自持久化保存【对方签名】到 <session_id>.jsonl.sig
```

#### 3.4.3 验签规则（核心约束）

> **任一方后续出示账本时，必须同时提供【自己的签名 + 对方的签名】。
> 缺一则判无效（invalid）。**

- 谁主张、谁举证：Alice 说"会话无降级"，她要出示 Bob 的签名来佐证
- Bob 手里的 `<sid>.jsonl.sig` 是**独立的第三方存证**，Alice 改不了
- **防分叉**：若 Alice 与 Bob 手中的账本 hash 不一致 → 立刻暴露有方篡改

#### 3.4.4 边界（MVP 内的诚实说明）

- **仍然假设双方私钥不泄露**——私钥全泄露是终极风险，超 MVP 范围
- **交换发生在 WS 信道上**——信道若被完全劫持，交换本身可被中间人替换（这属通联层/TLS 问题，路①范畴）
- **不做双向对账自动化**——MVP 只做"交换+保存"，主动对账（定期比对双方账本）留作 P2

> **H1 的最小生效条件**：交换协议 + 对方签名持久化 + 验签要求双签齐备。
> 三者缺一，"不可篡改"就不成立。

---

## 四、接入点（v0.2）

| 接入点 | 文件 | 做什么 | v0.2 变化 |
|:--|:--|:--|:--|
| ① 会话建立 | `secure_session.py` 握手成功处 | 写 `handshake`（含 nonce/fpr）+ 起账本 | 增记 nonce/fpr |
| ② 每帧解密 | `ratchet_decrypt` 及回退分支 | **全量**写 `frame` + 分级判定 | **全量记录**（H4）+ 分级（H3） |
| ③ 会话关闭 | `node.py` WS 断开处 | 写 `close` + 算 ledger_hash + **发起签名交换** | **增签名交换**（H1） |
| ④ 签名交换 | 新增 `ledger.py` 内 | 收/发对方签名，持久化 `<sid>.jsonl.sig` | **新增**（H1） |
| ⑤ 账本存储 | `agentlink/ledger.py` | 全量追加写 `~/.agentlink/ledgers/<sid>.jsonl` | 全量（H4） |
| ⑥ 查询接口 | CLI `agentlink ledger show <sid>` | 只读打印 + **双签校验**（缺对方签名标 invalid） | 增强验签 |

> ⚠️ **②号接入点仍是灵魂**：10-09 那行「回退普通解密」所在的代码路径，
> **必须**写一条带 `downgrade_class` 的 frame 事件。找不到该路径 = 设计没落地。

---

## 五、验证方案（v0.2）

复用 `e2ee_cross_machine_verify.py` 跨机链路，新增断言：

**验证 1：正常会话 → 账本无降级 + 双签齐备**
```
1. 跨机跑正常 @search（棘轮命中）
2. 断言 downgrade_count == 0
3. 断言 signatures.verified_both == true
4. 断言存在 signature_exchange 事件 且 双方签名均已持久化（<sid>.jsonl.sig 存在）
```

**验证 2：强制降级 → 分级正确**（回归 10-09 场景）
```
1. 人为制造棘轮未命中
2. 断言 downgrade_count >= 1
3. 断言该帧 downgrade_class ∈ {noise, suspicious, critical} 且 reason 具体
   （不是笼统的 "ratchet_miss"）
```

**验证 3（H1 核心）：单方篡改 → 验签失败**
```
1. 取一份合法账本，删改中间一条事件
2. 重算 hash 链 + 用本地私钥重签（模拟"单方改账本"）
3. 断言：仅凭【自己的签名】→ 判定 invalid（因为缺对方签名 / 对方签名对不上）
4. 断言：出示【双方签名】→ 对方签名校验失败 → 判定 tampered
```

**验证 4（H4）：全量帧记录**
```
1. 跑一次含 N 条正常帧 + 1 条降级帧的会话
2. 断言 events 中 frame 事件数 == N + 1（正常帧也在，未被"只记异常"丢弃）
```

**成功判据**：**验证 3 通过 = "单方改不了"从口号变成机制**（这是 v0.2 相对于 v0.1 的核心提升）。

---

## 六、与另外两个方向的关系（沿用）

```
路②（社会层）：
   会话可审计（本文 · MVP）
        ↓ 提供「事实」
   冲突降级协议（第二步）
        ↓ 提供「裁决」
   反趋同设计（第三步）
```

**可审计是地基**（仲裁需证据、声誉需历史、反合谋需可审计性）。
**v0.2 把地基里的"钢筋"——双签交换——补上了。**

---

## 七、风险与坦白（v0.2 修订）

| 风险 | 说明 | 缓解 | 状态 |
|:--|:--|:--|:--|
| ~~只记异常帧导致漏证~~ | ~~攻击者避免触发异常~~ | **改全量记录**（H4） | ✅ v0.2 已解决 |
| 降级误报/漏报 | 被审计代码自报 | 分级 + 冗余密档字段（H3） | ⚠️ 部分解决 |
| 单方篡改 | 签名不交换 | **签名交换 + 双签验签**（H1） | ✅ v0.2 已解决 |
| 私钥泄露 | 双签均失效 | 超 MVP 范围 | ❌ 未解决（已知） |
| 交换信道被劫持 | WS 明文 | 属通联层（路①/TLS） | ❌ 未解决（已知） |
| 存储膨胀 | 全量帧 | **会话结束 7 天后压缩归档**（不再靠丢弃事件） | ✅ v0.2 方案 |
| 拖慢会话 | 每帧写盘 | 内存累积 + 会话结束一次落盘 | ✅ 沿用 |
| 时间戳漂移 | 跨机时钟差 | seq 纳入 hash 链 + 记双向事件 | ✅ v0.2 强化 |

> **诚实标注**：v0.2 解决了 H1/H4，**部分**解决 H3，顺手覆盖 H5/H6 的轻量部分。
> **未解决**：私钥泄露、交换信道劫持、被审计代码自报的根本局限（需独立见证，P2）。
> 本设计仍是"社会机制第一步"，不是终点。

---

## 八、下一步

1. **评审 v0.2** → 重点确认 §3.4 签名交换协议的落地点（在 `node.py` 还是 `ledger.py`）
2. 落地顺序：`ledger.py`（含签名交换）→ 三个接入点改全量+分级 → CLI 加双签校验 → 四个验证脚本
3. 预计改动：**新增 ~1 文件 + 3 处钩子 + 1 CLI + 2 条协议步骤**，仍不动加密核心
4. **P1/P2 暂缓**：H2（Merkle tree / 外部锚定）、meta-audit、replay 保护、独立见证进程——按既定判断，私网自用场景优先级低

---

## 附：v0.1 → v0.2 逐条对照

| Kimi 编号 | 议题 | v0.1 | v0.2 | 采纳 |
|:--|:--|:--|:--|:--|
| **H1** | 签名交换 | ❌ 只签不换 | ✅ 强制交换+双签验签 | ✅ P0 采纳 |
| H2 | 增量验证/Merkle | ❌ 无 | ⏸️ 未做 | ❌ P1 暂缓 |
| **H3** | 降级判定 | ❌ 笼统 ratchet_miss | ✅ 三级分类+冗余字段 | ✅ P0 采纳 |
| **H4** | 只记异常帧 | ⚠️ 有该错误提法 | ✅ 撤销，全量记录 | ✅ P0 采纳 |
| H5 | 逻辑时钟 | ❌ 无 | 🔸 seq 纳入 hash 链 | 🔸 轻量预防 |
| H6 | DID 时序 gap | ❌ 无 | 🔸 记 nonce/fpr | 🔸 轻量预防 |
| 缺口1 | meta-audit | ❌ 无 | ⏸️ 未做 | ❌ P2 暂缓 |
| 缺口2 | replay 保护 | ❌ 无 | ⏸️ 未做 | ❌ P2 暂缓 |
| 缺口3 | CLI 权限 | ❌ 无 | ⏸️ 未做 | ❌ P2 暂缓 |

---

**相关文件：**
- v0.1 原稿：`会话可审计MVP设计-20261011.md`
- Kimi 测评：`会话可审计MVP-Kimi测评-20261011.md`
- 项目本体：（开发工作目录）
- 安全会话层：`agentlink/secure_session.py`
- 跨机验证：`e2ee_cross_machine_verify.py`
