# AgentLink 更新日志 (Changelog)

本文件记录 AgentLink 各版本的重要变更。版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

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
