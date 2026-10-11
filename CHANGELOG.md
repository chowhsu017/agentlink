# AgentLink 更新日志 (Changelog)

本文件记录 AgentLink 各版本的重要变更。版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> **版本口径**：里程碑 `v0.3`（文档/CHANGELOG 叫法）↔ 包版本号 `0.3.0`（semver，`pyproject.toml` /
> `agentlink.__version__`）↔ 会话账本数据结构 `ledger_version=1.2`。三者对应关系以本条为准。

## [v0.3.0] - 2026-10-12

> 主题：**跨机账本一致性**——让双方签**同一个**签名对象。

### 🐛 修复（关键）

- **H1 签名交换跨机结构性失效**：v0.2 让两端各建一本账本、各签【自己的】 hash，
  而两本账本因视角不同天然不同（`initiator/responder/ts/direction/帧数` 等）→
  `H_A ≠ H_B` 几乎必然 → 跨机诚实会话双签校验**必然失败**（假阴性，误判 tampered）。
  本版定义**唯一签名对象**：`sig_object = sha256(H_initiator_view ‖ H_responder_view)`
  （按会话角色定序，非本地视角）→ 两端算出同一对象 → 双签才真正成立。
- **签名按角色安放**：`my_sig` 必须放本端角色槽（响应方放 `responder` 槽），
  否则响应方验签必败。

### ✨ 新增

- **C1 双本拼接签名对象**（`compute_sig_object()`）：跨机双签从假阴性变成真有效。
- **C3 防分叉落地**：`verify()` 用「本端 hash + 对方 hash」重算 `sig_object` 并比对——
  任一 hash 被改即暴露（v0.2 的对方 `ledger_hash` 字段收到即弃，防分叉是纸面条款）。
- **C2 规范三字段**：① `initiator/responder` 两端写同一套 ② `direction` → **发送方 DID**
  ③ 握手 `nonce/fpr` 统一取发起方视角。
- **两轮签名交换**：先互发链尾 hash，再互发对 `sig_object` 的签名（`node._finalize_ledger`）。
- `<sid>.sig` 增 `sig_object` / `self_hash` / `peer_hash` / `role_order`。
- CLI `ledger show` 增 `sig_object` / 对端哈希展示。

### ✅ 测试

- 新增 5 项 v0.3 断言（验证 A/B/C/D + 落盘往返）+ 1 项真实 Ed25519 两轮交换 E2E。
- **46 passed**（v0.2 为 40），零破坏。
- 对照复现脚本：`tests/repro_cross_machine_ledger_mismatch.py`（v0.2 缺陷 vs v0.3 修复）。

### 🌐 真机跨机回归（验证 A，2026-10-12）

- 对端机 B（`peer-b`）同步升级 v0.3（4 文件 + `agentlink_p1.py` 增 `ledger_sig` handler）后重启 responder。
- **一次诚实会话：两端 `sig_object` 相同、双签齐备、真实 Ed25519 交叉验签通过**。
- 关键证据：`sig_object = sha256:f46739e1…`（双方一致）；降级 0。
- 对端机 B 侧的 `agentlink_p1.py` 新增了 WS `ledger_sig` 两轮交换 handler。

### 🧩 D3 修复：IPv6/IPv4 双栈兼容（2026-10-12）
**问题**：服务端 uvicorn 绑 `0.0.0.0`（只 IPv4）；macOS 对 `.local` 主机名 IPv6-first →
`websockets.connect(主机名)` 首试 IPv6 → 对端无监听 → **5s 超时**（httpx 有回退所以侥幸能连）。

**修法**：新增 `agentlink/netutil.py` 的 `prefer_ipv4_url()`，在所有出站连接点把 host 解析为 IPv4：
- `agentlink_call_peer.py` / `agentlink_responder_call.py`（替换 ad-hoc `_force_ipv4`）
- `agentlink/node.py` `call()`（peer WS + HTTP 一并归一）
- 逃生开关 `AL_PREFER_IPV6=1`（未来双栈环境）；`AL_NET_DEBUG=1` 打印解析

**实测**：主机名连接 **5.0s 超时 → 0.028s**（快 ~178 倍）；发起方→响应方 与 响应方→发起方 **双向均通**。
**新增测试**：`tests/test_netutil.py`（7 项）。**53 passed**（原 46）。

### 🔧 补：initiator 路径建账本（2026-10-12）

- 修 v0.2 遗留缺口：`on_accept()` 的 initiator（呼叫方）路径之前只建 cipher、不建账本。
- 现在呼叫方也会建账本（`is_initiator=True`）+ 记帧 + 封存。
- 新增测试 `test_v03_initiator_accept_creates_ledger`。**54 passed**（原 53）。

### ⚠️ 诚实说明

- 本版只修「跨机账本一致性」。**未解决**：私钥泄露、交换信道被劫持、
  被审计代码自报（需独立见证，P2）；**暂缓**：Merkle/外部锚定（P1）。
- 「验证 A（诚实跨机会话通过）」需**对端同步升级 v0.3** 才能跑真机。

---

## [v0.1.5] - 2026-09-19

> 主题：**把"死代码"变成"活能力"** + **诚实标注问题空间**。

### 📖 文档

- **README 新增「多智能体协作的开放问题」一节**：引用 Anthropic《Patterns and problems in
  multiagent systems》(2026-08)，说明本项目的会话生命周期方向与该报告所指"agent 之间缺乏
  平等同伴关系"的空白一致，同时**主动承认三个风险**（合谋/趋同/目标冲突升级）与**两个缺失**
  （追索权/仲裁、反合谋可审计性）。
- **REVIEWS.md 新增「领域参考」**：收录 Anthropic 该报告的关键结论与作者回应。
- **README「安全现状」表**：明确区分已具备（E2EE、对称棘轮、不变量断言）与已知不足（无 DH 棘轮）。

### 🐛 修复（关键）

- **对称棘轮接入主链路**：`SessionCipher.ratchet_encrypt/ratchet_decrypt` 虽早已实现，但**零调用点（死代码）**——
  实际调用的是普通 `cipher.encrypt()`，没有任何棘轮。现接入：
  每条消息用 HKDF 派生独立密钥 → 单条消息密钥泄露不牵连其他消息。

### 🧪 测试

- 新增 `TestRatchet`：棘轮往返 / 逐消息密钥唯一性 / **前向安全验证**。
- 修正 `test_channel_key`（原断言与"防假密钥"行为不符）。

### 🔧 工程

- 新增 CI（`.github/workflows/tests.yml`）：Python 3.10/3.11/3.12 矩阵跑 pytest + 不变量断言。

### ⚠️ 诚实说明

本版解决的是**对称棘轮**（消息级前向安全）。**DH 棘轮（双棘轮）仍未接入**，
长期私钥泄露后可回溯解密的风险**依然存在**。项目提供的是"通道"，不是"社会机制"。

---

## [v0.1.4] - 2026-08-30

> 针对协议可信性的三项加固（状态机 / 异步并发 / 不变量断言）。目标：从"能跑"到"可信"——堵住静默明文降级、占位符 DID 不对称、async 回调丢协程三类隐性风险。

### 🛡️ 新增（3 项加固）

- **协议状态机文档**：新增 `docs/协议状态机.md`，对齐 WebRTC SDP 握手思想（offer/answer/ice-candidate），定义 `IDLE/CALLING/RINGING/IN_SESSION` 离散状态、消息↔合法状态映射、加密协商中"谁该有公钥 / 谁该有 salt / 谁该有真实 DID"的权威归属，及 5 条协议不变量。
- **回调统一 await**：新增 `_maybe_await()` 辅助，所有 `on_ring/on_accept/on_data/on_hangup` 回调显式声明为 `Awaitable | None`，调用处统一安全 await——**修复 `on_accept` 原本同步调用未 await、async 回调静默不执行的遗留 bug**。
- **三重不变量断言 + 静默降级防护**：
  - `_peer_from_ctx`：加密路径前断言 `_call_context` 已 set（防"全仓无人赋值 → 一直明文"）。
  - `encrypt_payload`：加密前断言 `peer_did` 已解析为真实值（非 `placeholder` / 非 `did:wba:` 占位符），防 AEAD 关联数据不对称。
  - `on_data`：断言入站帧 `🔒` 前缀 ⟷ 本端 `e2ee_enabled` 一致，防前缀收发不对称。
  - 无 cipher / 明确文降级时打印醒目标记 `⚠️⚠️ 明文发送（不安全）`，绝不静默。

### 🧪 验证

- 新增 `e2ee_assert_test.py`：故意违反三个不变量，确认断言全部触发（有效而非摆设）。
- 回归 `e2ee_selftest_v3.py`：正常跨机占位符场景加密往返依旧全通，断言未误伤正常链路。

---

> 本次版本源于一台 Mac 与另一台 Mac 的真实局域网联调。E2EE 跨机加密通话 + 跨机资源调用（"远程调用对端本地能力"）首次实证跑通，并修复了联调中暴露的 5 个协议缺陷。

### 🐛 修复（5 个真实联调暴露的缺陷）

- **坏 import**：`signal_client.py` 顶层 `from agentlink_secure_session import ...` 找不到模块（真身在 `agentlink/secure_session.py`）。提供顶层 shim 兼容。
- **E2EE 握手断链**：`_call_context` 状态从未被写入，responder 永远拿不到 initiator 公钥 → 会话始终降级为明文。重构 call 握手：initiator 携带公钥、responder 写入 context、ring 响应回传盐（salt）供 initiator 复用一个对称 cipher。
- **"🔒" 前缀收发不对称**：`encrypt_payload` 加密后加 `🔒{b64}` 前缀，但 `on_data` 解码前未剥离 → 解密永远失败。修复解码前置剥离前缀。
- **AEAD 关联数据不对称（跨机必踩）**：`SessionCipher._ad_for_seq` 按排序后的双方 DID 对绑定关联数据；但 initiator 的 `peer_did` 是占位符（`did:wba:localhost-<port>`），responder 用真实 DID → 两侧 AD 不一致，跨机解密必失败。修复：ring 响应回传 responder 真实 `peer_did`，initiator 覆盖占位符。
- **async 回调未 await**：`on_ring` / `on_data` 是异步协程，但在 HTTP/WS 处理器里被同步调用 → 回调不执行 / 加密帧不解密。修复：检测 awaitable 后正确 `await`。

### ✨ 新增

- **跨机资源调用**：新增 `capability_service.py` —— 收到解密后的命令（如 `@search <关键词>`）时，执行对端指定的本地能力并将结果加密回传。演示了"远程调用对端本地资源"的能力边界。
- **交互式发送端**：新增 `send_interactive.py` —— 命令行交互式客户端，输入命令即加密发送、自动解密显示回传。所有机器信息（密钥路径 / IP / DID）均通过环境变量配置，不硬编码，便于安全分发。

### 🧪 验证

- 同机双 Agent 自测：E2EE 握手、🔒 前缀、占位符 DID 三种场景全部通过。
- 跨机实测（同一局域网两台 Mac）：`@search` 请求经端到端加密往返，本地素材库检索结果解密回显，数字与本机逐条核对一致。

---

## [v0.1.2] - 2026-08-05

- P1-2 会话劫持（空参数绕过）修复
- P0-1 / 0-3 salt 对称（`secure_session` 对齐）
- P0-4 DID 指纹绑定
- P1-1 history / members 鉴权

## [v0.1.1] - 安全修复批次

- P0 X3DH 对齐 + salt 对称
- DID 冒充防护
- 离线消息鉴权
- 频道假加密修复
- 会话劫持、频道越权
- 私钥权限、CORS、监听 127.0.0.1
- 簿记 opt-in

## [v0.1.0] - 纯净初始版

- 七个原语：呼叫 → 振铃 → 接受 → 数据帧 → 心跳 → 频道 → 挂断
- X25519 DH + ChaCha20-Poly1305 + Ed25519 签名 端到端加密
- DID 去中心化身份、信令发现、离线缓存
