# AgentLink — Agent-to-Agent 实时通信协议
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Protocol: AgentLink](https://img.shields.io/badge/Protocol-AgentLink-blue.svg)]()

> **不是聊天工具，是 agent 之间的通信底座。**  
> 七个原语搞定完整会话生命周期：呼叫 → 振铃 → 接受 → 数据帧 → 心跳 → 频道 → 挂断。  
> 端到端加密、去中心化身份（DID）、信令发现、离线缓存，全都有。

**版本**: 0.1.0 · **MIT 许可证**  
**跨平台**: macOS / Linux / Windows — 纯 Python，到哪都能跑

---

## 一分钟上手

```bash
# 安装（含信令服务依赖）
pip install git+https://github.com/chowhsu017/agentlink.git[full]

# 启动完整服务
agentlink serve --port 9765

# 另一台机器：生成密钥，连上来
agentlink keygen my-agent
```

搞定。你的 Agent 已经有了 DID 身份，可以呼叫、加密通信、加入频道。

---

## 为什么需要 AgentLink

| 现有问题 | AgentLink 的方案 |
|:---|:---|
| Agent 只能一问一答，没有连续会话 | 完整会话生命周期：呼叫→振铃→接通→数据流→挂断 |
| 数据明文传输，不安全 | 端到端加密（X25519 DH + ChaCha20-Poly1305 + Ed25519签名） |
| 不知道谁在线、在哪里 | 信令服务：DID注册/发现/在线状态/离线缓存 |
| 消息发了对方不在线 | 离线消息自动缓存，上线即推送 |
| 没有频道/群组概念 | 频道模式：订阅/广播/会员管理/历史持久化 |

**适用场景**：
- 🤖 **Agent 联邦**：不同 AI Agent 之间建立加密连接，协同工作
- 🔒 **私有化部署**：全在局域网，不上公网
- 🏢 **企业协同**：团队内 Agent 频道 + 一对一私信
- 📱 **跨平台互联**：macOS/Linux/Windows 全支持，装了就能通

---

## 架构概览

```
┌─────────────────────────────────────────────────────┐
│                     AgentLink                        │
│  ┌──────────────────────────────────────────────┐   │
│  │  会话层 (P1)                                  │   │
│  │  call_req → ring → accept → data → hangup    │   │
│  │  heartbeat / timeline / history               │   │
│  ├──────────────────────────────────────────────┤   │
│  │  频道 & Presence (P2)                         │   │
│  │  ChannelRelay / PresenceFederator / 广播      │   │
│  ├──────────────┬───────────────┬────────────────┤   │
│  │  身份 (DID)   │  加密 (E2EE)  │  信令 (发现)    │   │
│  │  Ed25519     │  X25519+Cha  │  REST+WS       │   │
│  │  DID 凭证     │  Cha20-Poly  │  SQLite 持久化    │   │
│  └──────────────┴───────────────┴────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## 安装

### pip 安装（推荐）

```bash
# 完整安装（信令服务 + 频道 + Presence）
pip install git+https://github.com/chowhsu017/agentlink.git[full]

# 最小安装（仅加密 + 客户端）
pip install git+https://github.com/chowhsu017/agentlink.git
```

### 从源码安装

```bash
git clone https://github.com/chowhsu017/agentlink
cd agentlink
pip install -e ".[full]"
```

**Windows 用户**：同上，一模一样。前提是装了 Python >= 3.10。

---

## CLI 工具

```bash
agentlink serve         # 🚀 一键启动完整服务（信令+频道+Presence）
agentlink signal        # 📡 仅启动信令服务（轻量模式）
agentlink keygen <名>   # 🔑 生成密钥对
agentlink encrypt       # 🔒 端到端加密消息
agentlink decrypt       # 🔓 解密消息
agentlink channel       # 📢 频道管理
```

### `agentlink serve`

启动完整服务，一行命令搞定所有能力：

```bash
agentlink serve --port 9765

# 输出：
# 🚀 AgentLink 服务启动 @ 0.0.0.0:9765
#    DID:      did:agentlink:signal:XXXX
#    📡 信令:     ws://0.0.0.0:9765/signal/ws
#    📢 频道:     http://0.0.0.0:9765/channel/create
#    👥 Presence:  http://0.0.0.0:9765/signal/status
```

可选参数：

| 参数 | 默认值 | 说明 |
|:------|:-----|:-----|
| `--port` | 9765 | 监听端口 |
| `--host` | 0.0.0.0 | 监听地址 |
| `--db` | ~/.agentlink/signal.db | 信号数据库 |
| `--key` | ~/.agentlink/signal_key.json | 服务密钥 |
| `--channel-db` | ~/.agentlink/channels.db | 频道数据库 |
| `--log-level` | warning | 日志级别 |

---

## 两台机器互联

### 机器 A（你的）→ 启动服务

```bash
agentlink serve --port 9765
```

记下输出的 DID：`did:agentlink:signal:XXXX`

### 机器 B（朋友的）→ 生成身份，接入

```bash
agentlink keygen friends-agent
# 输出 DID: did:agentlink:friends-agent:YYYY
# 输出密钥文件: agentlink_friends-agent.key.json
```

### 交换公钥，建立加密通道

```python
from agentlink import generate_keypair, encrypt_message, decrypt_message
from agentlink import compute_shared_secret, derive_session_key

# 各自加载自己的私钥和对方的公钥
# 导入对方密钥文件即可——不需要交换私钥！
alice = load_keypair("alice.key.json")
bob_pub = load_keypair("bob.key.json")  # 这里只取公钥，私钥只有 bob 持有

# DH 密钥协商
shared = compute_shared_secret(alice.enc_private, bob_pub.enc_public)
sk = derive_session_key(shared)

# 现在两边用同一个 sk 加密通信
enc = encrypt_message(sk, b"Hello from Alice!")
plain = decrypt_message(sk, enc)
```

---

## API 参考

### 加密模块 (`agentlink.crypto`)

基于 `cryptography` 库的完整椭圆曲线密码套件。

```python
from agentlink import (
    generate_keypair, load_keypair, save_keypair,
    compute_shared_secret, derive_session_key,
    encrypt_message, decrypt_message,
    sign_message, verify_signature,
    create_did_binding, verify_did_binding,
    SessionCipher,
)
```

| 函数 | 说明 |
|:------|:-----|
| `generate_keypair(name)` | 生成 Ed25519(签名) + X25519(加密) 双密钥对 |
| `compute_shared_secret(私钥, 对方公钥)` | X25519 DH 密钥交换 |
| `derive_session_key(shared)` | HKDF-SHA256 派生 32 字节会话密钥 |
| `encrypt_message(key, plaintext)` | ChaCha20-Poly1305 AEAD 加密 |
| `decrypt_message(key, encrypted)` | 解密（验证失败抛异常） |
| `sign_message(私钥, msg)` | Ed25519 签名 |
| `verify_signature(公钥, msg, sig)` | 验证签名 |
| `SessionCipher` | 封装类，自动管理会话密钥 |

### 信令客户端 (`agentlink.signal_client`)

```python
from agentlink.signal_client import SignalClient

client = SignalClient(server_url="http://your-server:9765")
await client.register(did, name, enc_public_b64, http_url, ws_url)
agents = await client.discover()
```

### 频道中继 (`agentlink.p2`)

```python
from agentlink.p2 import ChannelRelay

relay = ChannelRelay(db_path="channels.db")
relay.create_channel("dev-team", "开发组", "did:alice")
relay.join_channel("dev-team", "did:bob")
relay.broadcast("dev-team", "did:alice", "部署完成，请检查！")
```

---

## 协议草案

详见仓库根目录 `agentlink_bookkeeping_spec.md`。

协议涵盖：

1. **会话原语**: 7 个原语的定义、时序、状态机
2. **安全模型**: DH 密钥协商、AEAD 加密、DID 身份绑定
3. **传输协议**: JSON-RPC 2.0 over HTTP/WebSocket
4. **频道模式**: 订阅/广播/会员/历史/E2EE

---

## 技术栈

| 层级 | 技术 |
|:------|:-----|
| 身份 | Ed25519 签名密钥对（DID 格式） |
| 密钥交换 | X25519 Diffie-Hellman |
| 消息加密 | ChaCha20-Poly1305（AEAD） |
| 序列化 | JSON-RPC 2.0 over HTTP/WebSocket |
| 信令 | FastAPI + SQLite + WebSocket |
| 心跳 | 30s 间隔，3 次缺失离线 |
| 频道 | 独立中继 / 支持 E2EE 组密钥 |
| 语言 | Python ≥3.10（跨平台） |
| 依赖 | cryptography + httpx + websockets + fastapi + uvicorn |

---

*AgentLink v0.1 — 让 Agent 们能好好说话。*  
*2026-08-05*

---

## 第三方评价

> "AgentLink不是一款App，而是一个面向开发者的基础设施工具。它的价值在于为AI应用提供了一个标准化、安全、可私有化的通信层，让多个AI智能体从'单机'走向'联网协作'。"
> — **DeepSeek**, 2026-08-05

更多评价见 [REVIEWS.md](REVIEWS.md)。
