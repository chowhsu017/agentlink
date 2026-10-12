# Headscale 自建预案（备查，mini 到货后再定）

> 建立：2026-10-12 ｜ 定位：若最终决定"连 Tailscale 公司都不让它知道我的设备"，照此自建。
> ⚠️ **状态：预案，未执行。** 决策点：先用官方 Tailscale 把系统跑通，**跑通后**再评估是否切换。
> 关联：`10-06 公网访问与通联设计`（附录含 Headscale 利弊）、`10-07 国内Tailscale可用性`、`AgentLink-家庭多机场景整合设计`

---

## 〇、先想清楚：为什么要自建（收益边界）

| 层 | 官方 Tailscale | 自建 Headscale |
|:--|:--|:--|
| 数据内容 | ✅ WireGuard E2E（官方看不到内容）| ✅ 同 |
| **设备元数据**（谁有几台、在线）| ❌ **经过 Tailscale 公司** | ✅ 全在自己手里 |
| 控制面可用性 | 依赖官方 | 依赖自己的 VPS |
| 需公网入口 | 否 | 🔴 **是**（VPS + 域名）|
| 运维 | 0 | 长期税 |

**自建的唯一真实收益 = "元数据不经第三方"。** 内容机密性两者相同。
**代价 = 一台国内 VPS + 域名 + 长期运维 + 自建 DERP。**

→ **划算与否，取决于"元数据不外流"对你值多少。** 先用官方跑通，届时用实感决定。

---

## 一、架构

```
[MacBook] ─┐
           ├─ WireGuard 直连（数据面，端到端加密，同官方）
[Mac mini] ─┘
     ↕ 控制面（仅协调：谁是谁、ACL、密钥分发）
[国内 VPS: Headscale]  ← 唯一公网暴露点（你自建）
     ↕ 中继（打洞失败时）
[国内 VPS: derper]     ← 自建 DERP 中继
```

**关键**：客户端**仍用官方 Tailscale App**，只把"登录服务器"改成你的 Headscale 地址。**数据面完全一样。** AgentLink 代码**一行不改**（它只连 tailnet IP/名字）。

---

## 二、前置条件

| 项 | 要求 |
|:--|:--|
| 国内 VPS | ¥20-30/月，1核1G 起（如阿里云/腾讯云轻量）|
| 域名 | 一个（用于 VPS 的 TLS 证书 + Headscale 登录地址）|
| 备案 | ⚠️ 国内 VPS + 域名对外服务**通常需备案**——纯自用可评估风险；不想备案 → 用境外 VPS（但延迟高）|
| 证书 | Let's Encrypt（acme.sh / caddy 自动）|

---

## 三、部署步骤（概要）

```
1. VPS 装 Headscale（Docker 最省事）
2. 配 TLS 证书（caddy 反代 或 acme.sh 直挂）
3. 建 tailnet + 生成 pre-auth key
4. 各设备：官方 Tailscale App → 登录服务器改成 https://headscale.你的域名 → 用 pre-auth key 加入
5. 自建 derper（DERP 中继）→ 写进 Headscale 的 derp_map
6. 测：tailscale status（direct/relay）+ tailscale ping
```

**踩坑预警**（10-06 文档已列）：TLS 证书、需公网入口、DERP 配置、客户端接入——**首次半天到一天，踩坑 2-3 天**。

---

## 四、与 AgentLink 的对接点

| 项 | 变化 |
|:--|:--|
| AgentLink 代码 | **零改动**（只连 tailnet 名字/IP）|
| `agentlink_peers.json` | 主机名从 `xxx.ts.net` 换成 Headscale 分配的 MagicDNS 名（若启用）或 100.x.y.z |
| 服务 bind | 仍只绑 tailnet 接口（`--host $(tailscale ip -4)`）|
| 安全性 | 不变（都是 WireGuard）|

→ **这就是"先官方、后 Headscale 无缝切换"的底气**：AgentLink 层完全不受影响。

---

## 五、DERP 自建要点

- `derper` 单进程（Go 编译，或 Docker）
- 需在 Headscale 配置 `derp_map` 指向你的 derper
- 国内 VPS 带宽是瓶颈（中继吃带宽，选按流量/带宽够的）
- 判据同官方：`tailscale netcheck` 看延迟

---

## 六、决策清单（mini 到货后逐条过）

```
□ 官方 Tailscale 已跑通（双机 + AgentLink）
□ 实测 tailscale status：direct 还是 relay？
□ 用下来，我介意"Tailscale 公司知道我有几台设备"吗？
    ├─ 不介意 → 不建 Headscale，收工
    └─ 介意 → 进入下一步
□ 有没有国内 VPS（¥20-30/月）+ 域名？
□ 能接受首次 1-3 天的部署 + 长期运维吗？
□ 以上都 yes → 按第三节部署；否则 → 保持官方
```

---

*预案：2026-10-12 · Strong（盛朗）· 未执行，等 mini 到货 + 实感决策*
