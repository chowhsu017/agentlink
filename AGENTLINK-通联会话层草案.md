# AgentLink Protocol (通联系列) — 草案 v0.1

> 站在 ANP 的肩膀上，补上 Agent 实时会话这块拼图。
> ANP 提供身份（did:wba）、寻址（WNS）、加密（E2EE）、跨域路由（P8）。
> AgentLink 提供会话生命周期（呼叫↔振铃↔接通↔挂断）+ 实时流。

---

## 1. 定位

```
        通信模式光谱
  ┌─────────────────────────────►
  消息投递         实时会话
  (ANP/A2A)       (AgentLink)
  └───── 功能复杂度 ────►
```

**核心差异：**

| 维度 | ANP | AgentLink |
|------|-----|---------|
| 通信模型 | 请求-响应 / 异步投递 | 对等会话（呼叫→接通→数据交换→挂断） |
| 状态 | 无状态，每次调用独立 | 有状态，会话生命周期管理 |
| 数据流 | 一次性消息体 | 连续流（语音/数据/事件） |
| 寻路 | 发现→调用 | 发现→拨号→建立→维护 |
| 错误处理 | 超时重试 | 重拨、断线重连、心跳保活 |
| 广播/频道 | 群组消息（有序投递） | 频道模式（无需加入，监听即可） |
| 在线状态 | 明确不做 | 核心能力（空闲/忙线/隐身） |

---

## 2. 核心原语

### 2.1 会话生命周期

```
┌───┐              ┌───┐
│ A │              │ B │
└─┬─┘              └─┬─┘
  │                  │
  │  call_req ──────►│  ← 发起呼叫（含能力声明）
  │                  │
  │  ◄──── call_ring │  ← 振铃通知
  │                  │
  │  call_ring_ack ─►│  ← 确认振铃可达
  │                  │  (可选) 3次无应答 → 超时挂断
  │                  │
  │  ◄── call_accept │  ← 对方接通  / 或 call_reject / call_busy
  │                  │
  │══ session_begin ═╡  ← 会话建立
  │  ║            ║  │
  │  ║ data_frame  ║  │  ← 双向数据流（结构化/二进制/语音块）
  │  ║ heartbeat   ║  │  ← 保活心跳
  │  ║            ║  │
  │══ session_end ═══╡  ← 任一方发起挂断
  │                  │
  │  hangup ────────►│
  │  ◄─── hangup_ack │
  │                  │
```

### 2.2 消息原语定义

所有消息复用 ANP 的传输机制（JSON-RPC 2.0 over HTTP/WebSocket），Profile 名为 `agentlink.session.v1`。

#### 2.2.1 `agentlink.call_req`

发起方 → 目标方

```json
{
  "jsonrpc": "2.0",
  "method": "agentlink.call",
  "params": {
    "meta": {
      "profile": "agentlink.session.v1",
      "sender_did": "did:wba:alice.example.com:agent",
      "target_did": "did:wba:bob.example.com:agent",
      "security_profile": "agentlink-e2ee"
    },
    "body": {
      "session_id": "uuid-v4",              // 呼叫方生成
      "caller_name": "Alice",
      "capabilities": {                      // 本方支持的会话能力
        "stream_types": ["text", "json", "audio/opus", "binary"],
        "max_session_sec": 3600,
        "heartbeat_interval_sec": 30,
        "e2ee": true,
        "nat_traversal": ["direct", "relay"]
      },
      "context": {                           // 可选：呼叫上下文
        "reason": "ask_about_case",
        "priority": "normal"
      }
    }
  }
}
```

#### 2.2.2 `agentlink.call_ring`

目标方收到后返回振铃通知。

```json
{
  "jsonrpc": "2.0",
  "method": "agentlink.call_ring",
  "params": {
    "meta": {
      "profile": "agentlink.session.v1",
      "sender_did": "did:wba:bob.example.com:agent",
      "target_did": "did:wba:alice.example.com:agent"
    },
    "body": {
      "session_id": "uuid-v4",
      "ring_at": "2026-07-28T07:30:00Z",
      "timeout_sec": 30
    }
  }
}
```

#### 2.2.3 `agentlink.call_accept` / `agentlink.call_reject` / `agentlink.call_busy`

```json
// 接通
{
  "method": "agentlink.call_accept",
  "params": {
    "meta": { "profile": "agentlink.session.v1", ... },
    "body": {
      "session_id": "uuid-v4",
      "accepted_at": "2026-07-28T07:30:05Z",
      "selected_stream": "json",
      "selected_e2ee": true
    }
  }
}

// 拒接
{
  "method": "agentlink.call_reject",
  "params": {
    "meta": { "profile": "agentlink.session.v1", ... },
    "body": {
      "session_id": "uuid-v4",
      "reason": "busy"
    }
  }
}

// 占线（自动）
{
  "method": "agentlink.call_busy",
  "params": {
    "meta": { "profile": "agentlink.session.v1", ... },
    "body": {
      "session_id": "uuid-v4",
      "in_session_with": "did:wba:charlie.example.com:agent"
    }
  }
}
```

#### 2.2.4 `agentlink.data_frame`

会话建立后的数据传输：

```json
{
  "method": "agentlink.data",
  "params": {
    "meta": {
      "profile": "agentlink.session.v1",
      "session_id": "uuid-v4",
      "seq": 42
    },
    "body": {
      "type": "json",           // text | json | audio/opus | binary
      "payload": { ... },       // 具体数据
      "ack_requested": false
    }
  }
}
```

传输层推荐 WebSocket（`ws://` — 适合双向实时流），也可用 HTTP 长轮询（fallback）。

#### 2.2.5 `agentlink.heartbeat`

```json
{
  "method": "agentlink.heartbeat",
  "params": {
    "meta": {
      "profile": "agentlink.session.v1",
      "session_id": "uuid-v4"
    },
    "body": {
      "seq": 1,
      "timestamp": "2026-07-28T07:30:30Z"
    }
  }
}
```

心跳缺失 N 次后任一方可主动挂断（默认：3 次 × 30s = 90s 无响应）。

#### 2.2.6 `agentlink.hangup`

```json
{
  "method": "agentlink.hangup",
  "params": {
    "meta": {
      "profile": "agentlink.session.v1",
      "session_id": "uuid-v4"
    },
    "body": {
      "initiator": "local",      // local | remote | timeout | error
      "reason": "user_hangup",
      "summary": {
        "duration_sec": 187,
        "frames_sent": 342,
        "frames_received": 338
      }
    }
  }
}
```

### 2.3 频道（Channel）模式

扩展群组概念：**频道 = 单向/双向广播通道**，参与者无需"加入群组"，只需"订阅频道"。

```
频道 ────► Agent C
        ────► Agent D
        ────► Agent E (订阅者，只收不发)
```

```json
// 加入频道
{
  "method": "agentlink.channel.subscribe",
  "params": {
    "meta": { "profile": "agentlink.session.v1" },
    "body": {
      "channel_id": "case-2026-001",
      "mode": "readwrite"     // readonly | readwrite
    }
  }
}

// 频道广播
{
  "method": "agentlink.channel.broadcast",
  "params": {
    "meta": { "profile": "agentlink.session.v1", "channel_id": "case-2026-001" },
    "body": {
      "type": "json",
      "payload": { "event": "new_evidence", "file": "..." }
    }
  }
}
```

### 2.4 在线状态（Presence）

ANP 明确不做的，AgentLink 补上：

```json
{
  "method": "agentlink.presence.update",
  "params": {
    "meta": { "profile": "agentlink.session.v1" },
    "body": {
      "status": "idle",               // idle | busy | invisible | away
      "current_session": null,        // null 或在会话中时填 session_id
      "available_since": "2026-07-28T07:00:00Z",
      "capabilities": { ... }
    }
  }
}
```

Presence 发布方式：WNS 辅助发现 + 可选 WebSocket 订阅（Pub/Sub 模式）。

---

## 3. 与 ANP 的集成方式

```
            AgentLink 会话层 (你的协议)
  ┌─────────────────────────────────────┐
  │  call_req / accept / hangup / ...  │
  │  heartbeat / data_frame            │
  │  channel / presence                │
  ├────────────── ANP 基础设施 ────────┤
  │  did:wba 身份                      │
  │  WNS 寻址                          │
  │  P5 端到端加密                     │
  │  P8 跨域路由                       │
  │  Agent Description + OpenRPC      │
  └─────────────────────────────────────┘
```

### 集成接口（以 Agent Description 声明为例）

在 Agent Description 的 `interfaces` 数组中新增：

```json
{
  "type": "AgentLinkSessionInterface",
  "profile": "agentlink.session.v1",
  "binding": "jsonrpc-2.0",
  "url": "https://my-agent.example.com/agentlink",
  "ws_url": "wss://my-agent.example.com/agentlink/ws",
  "methods": [
    "agentlink.call",
    "agentlink.hangup",
    "agentlink.channel.subscribe",
    "agentlink.channel.broadcast",
    "agentlink.presence.update"
  ],
  "capabilities": {
    "stream_types": ["text", "json", "audio/opus", "binary"],
    "max_session_sec": 3600,
    "nat_traversal": ["direct", "direct-https", "relay"]
  }
}
```

### DID Document 扩展

ANP 目前用 `ANPMessageService` 做服务发现。AgentLink 可复用同一机制，新增一个 `AgentLinkService` 类型：

```json
{
  "id": "did:wba:example.com:agent#agentlink",
  "type": "AgentLinkService",
  "serviceEndpoint": "https://my-agent.example.com/agentlink",
  "wsEndpoint": "wss://my-agent.example.com/agentlink/ws"
}
```

存在 ANP 社区讨论中，暂作为草案提出。

---

## 4. 实现路线图

| 阶段 | 内容 | 预估 |
|------|------|------|
| P0 | 本机双进程 demo：Agent A 呼叫 Agent B → 振铃 → 接通 → 数据交换 → 挂断 | 1 天 |
| P1 | WebSocket 双向流 + 心跳保活 + 断线重连 | 2 天 |
| P2 | 频道模式 + Presence 发布/订阅 | 2 天 |
| P3 | 封装为 Python 库 `agentlink`，对接 ANP SDK | 2 天 |
| P4 | 集成到 StrongAI App 做 P2P 通信 | 待定 |
| P5 | 语音流（WebRTC 桥接） | 待定 |

---

## 5. 开放问题

- **NAT 穿透**：纯 P2P 需要 STUN/TURN，中继模式用 ANP P8 的跨域路由？还是独立部署 relay？
- **会话持久化**：如果一方断线后重连，是否恢复会话状态？
- **群组会话**：多方实时会话（3+ 个 Agent）——走频道模式还是独立的多方信令？
- **与 ANP E2EE 的交互**：AgentLink 会话层加密 = 复用 P5 还是独立密钥协商？
- **信令 vs 媒体分离**：call_req/accept/hangup 走 JSON-RPC（ANP 原生），data_frame 走 WebSocket——是否合理？

---

*草案版本：v0.1 — 2026-07-28*
*下一步：跑通 P0 demo，验证会话生命周期语义*
