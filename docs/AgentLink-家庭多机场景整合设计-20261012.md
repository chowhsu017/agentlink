# AgentLink · 家庭多机场景整合设计

> 建立：2026-10-12 ｜ 定位：把 AgentLink 从"通用协议玩具"收敛为**"家庭多机（Mac mini 常驻算力节点 + MacBook 移动终端）的会话层"**
> 前置文档（已存在，不重复）：
> - `Mac-mini迁移包/docs/公网访问与通联设计-20261006.md`（Tailscale 路线全文）
> - `Mac-mini迁移包/docs/国内Tailscale可用性-决策清单-20261007.md`（国内可达性实测）
> - `Strong财经/Mac-mini迁移与双机架构方案-20260930.md`（盘位/迁移）
> ⚠️ 状态：设计稿，mini 未到货

---

## 〇、一句话结论

**Tailscale 是传输底座，AgentLink 是会话层。两者不互斥、不重叠。**
- Tailscale 解决：**穿透 + 发现 + 加密隧道**（WireGuard）
- AgentLink 解决：**会话生命周期 + 资源调用语义 + 应用层身份（DID）+ 审计**

→ **由此导出本设计的最大取舍：P2-1（换 Noise/自研 E2EE）砍掉。**

---

## 一、分层架构（定稿）

```
┌─────────────────────────────────────────────────────────┐
│  应用层：笔记本「一句话连回家」—— agentlink connect mac-mini │
├─────────────────────────────────────────────────────────┤
│  AgentLink 会话层（本项目）                                │
│   · 七原语会话生命周期（call→ring→accept→data→hb→chan→hangup）│
│   · 资源调用应用协议（@search / @run <模型任务>）           │
│   · 应用层身份：DID + Ed25519 消息签名（防篡改）            │
│   · 会话账本（审计，可选）                                 │
├─────────────────────────────────────────────────────────┤
│  Tailscale（第三方，传输层）                               │
│   · WireGuard 端到端加密（传输加密由此提供，非 AgentLink）   │
│   · NAT 穿透 / DERP 中继 / MagicDNS 固定设备名             │
│   · 设备即身份（非密码），100.x.y.z 私网                    │
├─────────────────────────────────────────────────────────┤
│  硬件：Mac mini（家，常驻算力/素材） ↔ MacBook（移动终端）   │
└─────────────────────────────────────────────────────────┘
```

**🔴 分工铁律**：
| 能力 | 归属 | 说明 |
|:--|:--|:--|
| 传输加密 | **Tailscale** | WireGuard，不再由 AgentLink 自研 |
| 穿透/发现 | **Tailscale** | MagicDNS 名字恒定，换网不失效 |
| 会话语义 | **AgentLink** | 这是它唯一该独占的东西 |
| 应用层防篡改 | **AgentLink** | Ed25519 签名（WireGuard 之上再签一层，防应用层伪造）|
| 身份 | 两者都有 | Tailscale 管"设备"，AgentLink 的 DID 管"会话主体" |

---

## 二、✓ 决策落实（老哥已定）

| 决策 | 结论 | 影响 |
|:--|:--|:--|
| **P2-1 换 Noise** | ❌ **砍掉** → 改为"仅应用层 Ed25519 签名" | 消除最大工程风险与 bug 面；README 安全口径改写 |
| **P2-2 Merkle 账本** | ⬇️ 降级为 P3（自用场景审计需求弱） | 设计已存 `P2-2-Merkle账本-设计-20261012.md`，备查 |
| **P2-3 死代码清理** | ✅ 照做 | 顺手 |
| **DERP 自建** | ⏳ 到货实测再定（备选方案见 §5） | 按 10-07 决策清单自测 |

---

## 三、P2 重排（针对真实场景）

| 优先级 | 项 | 内容 | 预估 |
|:--|:--|:--|:--|
| **P0** | **D-A 组网** | mini+MacBook 同 tailnet；MagicDNS 固定名；**服务只 bind tailnet 接口**（不绑 0.0.0.0）| 到货后 1h |
| **P0** | **D-C 常驻** | mini 上 AgentLink 走 **launchd 保活**（照搬 zheng 机经验）| 1h |
| **P1** | **D-B 配置固化** | `agentlink_peers.json` 用 tailnet 名（`mac-mini.<tailnet>.ts.net`），不写 IP | 1h |
| **P1** | **D-D 一行连接** | `agentlink connect <名>`，固化 host/端口/密钥路径 | 半天 |
| **P1** | **安全口径改写** | README：E2EE → "传输加密由 WireGuard(Tailscale) 提供 + 应用层 Ed25519 签名" | 1h |
| **P2** | **D-E 资源扩展** | `@search` 扩成 `@run <模型任务>`（mini 上跑 Ollama，笔记本发任务）| 1天 |
| **P3** | P2-2 Merkle / P2-3 清理 | 见前述 | 按需 |

**关键变化**：**原来的"安全重写"（P2-1，1-2 周）整个消失了**——因为 Tailscale 兜住了。**整体交付周期从"1-3 个月"压到"mini 到货后 1 周内可用"。**

---

## 四、安全边界（针对"同网段也要防"）

老哥要求：**同网段别人也要防**。这对 AgentLink 反而是**好消息**（威胁模型变清晰）：

### 威胁模型
| 威胁 | Tailscale 挡不挡 | AgentLink 挡不挡 |
|:--|:--:|:--:|
| 同 WiFi 陌生人扫描端口 | ✅ 挡（设备隐身，扫不到）| — |
| 同 WiFi 陌生人访问 9765 | ✅ 挡（不在 tailnet 看不见）| — |
| 公网扫描 | ✅ 挡 | — |
| **tailnet 内**某设备被入侵后冒充 | ❌ | 🟡 DID+签名可识别身份异常 |
| 应用层伪造消息 | ❌（传输层只管通道）| ✅ **Ed25519 签名防伪** |

→ **"同网段防"由 Tailscale 全包；AgentLink 补"应用层身份与防伪"。** 分工干净。

### 🔴 必须做的加固（三条）
1. **服务只 bind tailnet 接口**，不绑 `0.0.0.0`
   ```bash
   # 反例（现在的 zheng 机就是这样，暴露给家庭局域网）：
   agentlink serve --host 0.0.0.0 --port 9765
   # 正解（只绑 tailscale 的 100.x.y.z）：
   agentlink serve --host $(tailscale ip -4) --port 9765
   ```
   ⚠️ **这是本设计对你现有部署的修正**：zheng 机的 `0.0.0.0` 应改为只绑 tailnet。
2. **macOS Tailscale 开"接受入站连接"**（否则 ping 通但连不上端口——10-06 文档已记）
3. **mini 禁休眠**（否则 Tailscale 断，远程失联——迁移包 `11-常开机节能设置.sh`）

---

## 五、DERP 自建备选方案（到货实测再定）

按 10-07 决策清单：**先测，别急着自建**。

```bash
# 到货后第一件事（两端都登录 tailnet 后）：
tailscale status          # 看 direct 还是 relay
tailscale ping <对端100.x> # pong via DERP = 走中继；via 192.168 = 直连
tailscale netcheck        # 各 DERP 节点延迟
```

**判据**：
- 显示 **direct** → 无需处理，正常用
- 显示 **relay** 且延迟不可接受 → 二选一：
  - **自建 DERP**（国内 VPS，¥20-30/月）：`derper` 单进程，加 tailnet ACL 里 `derp_map`
  - **换 EasyTier**（需重学，不推荐——放弃 Tailscale 生态）

**⚠️ 对 AgentLink 的特化**：资源调用（传素材库搜索结果）**走境外 DERP 会很痛**。若实测 relay 且慢，**自建 DERP 优先级要提到 P0**。

---

## 六、落地步骤（mini 到货后照此跑）

| 步 | 动作 | 命令/文档 | 预期 |
|:--|:--|:--|:--|
| 1 | 双机装 Tailscale + 同账号登录 | 10-06 文档 §三 | `tailscale status` 互见 |
| 2 | **测穿透质量** | §5 命令 | 判 direct/relay |
| 3 | mini 装 AgentLink 依赖 + 迁数据 | 迁移方案 A 类（≈12GB）| — |
| 4 | mini 起 `agentlink serve`（bind tailnet）| `--host $(tailscale ip -4)` | 9765 只对 tailnet |
| 5 | mini 配 launchd 保活 | 照搬 `com.strong.agentlink.server.plist` | 自启+自愈 |
| 6 | MacBook 配 `agentlink connect mac-mini` | D-D | 一句话连 |
| 7 | 跑 `e2ee_cross_machine_verify.py` 验握手 | 现有脚本 | 通 |
| 8 | 扩 `@run` 资源调用 | D-E | 笔记本发任务→mini 跑 |

---

## 七、README / 定位改写建议

**现状**：README 自称"E2EE 通信底座"，安全表列一堆 ❌（无棘轮等）——**这是负债**。

**建议改写为**：
> AgentLink 是**家庭/局域网多机的 agent 会话层**。传输加密由 **WireGuard（Tailscale）** 提供；本协议负责**会话语义（七原语）+ 资源调用 + 应用层身份签名（Ed25519）**。
> 威胁模型：**信任 tailnet 传输层**；防御重点在"应用层身份与防伪"，不在"自研密码学"。

**好处**：
- 甩掉"DIY 密码学"这个最大软肋（不再自研加密）
- 消除"无棘轮/无审计"的黑历史（传输层用成熟 WireGuard）
- 定位从"万能底座"收敛到"我的机器之间"——**诚实、可交付**

---

## 八、诚实说明（写进 README）

- **不防"tailnet 内设备被入侵"**：Tailscale 假设设备可信；设备沦陷则可冒充。
- **依赖第三方**：Tailscale 控制面是它的服务器（数据 E2E 加密，它看不到内容，但知道你有几台设备）；介意 → 自建 Headscale（见 10-06 附录）。
- **Tailscale 挂了**：远程连不上（局域网不受影响）。
- **应用层签名 ≠ 机密性**：Ed25519 防"伪造/篡改"，不提供机密性——机密性由 WireGuard 提供。别混淆。

---

## 九、与"通用协议"路线的关系（不迷路）

本设计**收敛**了 AgentLink 的定位，但不否定它的通用性：
- **家庭多机** = 第一个**真实用例**（先证明"非它不可"）
- 若将来要对外（朋友/开源用户）→ 回到"这层之上加通用性"，但那时的安全已由各自 tailnet 兜住
- **先自用跑通 → 再谈推广**（呼应"从玩具到应用"的判断：第五关"有人用"要先从"自己用"过）

---

*设计：2026-10-12 · Strong（盛朗）· 关联 P-002（评估工具先被评估）、TOOLS.md 的 AgentLink 单一真源部署*
