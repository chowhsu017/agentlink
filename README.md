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

# 注意：信令客户端需要传入 state(含 name/http_url/ws_url) 和 secure(E2EE 管理器)
# 通过 create_agent_app / create_secure_agent 构建，而非旧文档的 server_url 写法
state, secure = create_secure_agent("my-agent", 18763, keypair_path="my.key.json")
client = SignalClient(state, secure, "http://your-server:9765")
await client.register()          # 注册到信令服务
agents = await client.list_online()   # 查看在线 agent
found = await client.find("did:agentlink:bob:xxxx")   # 查找
await client.connect_ws()        # 保持 WS 长连（在线 + 收消息）
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

## 实战：跨机端到端加密 + 远程资源调用

> 两台真正的 Mac 在同一个局域网内，不经过云端，跑通了「端到端加密通话 → 远程调用对端本地能力」完整链路。

### 怎么跑（两台机器，一台作服务端/执行端，一台作客户端/请求端）

**服务端/执行端**（例如有素材库、算力、脚本的那台）：
```bash
# 启动完整 agent：HTTP + WS 端点 + 注册信令 + 保持在线
python e2ee_agent_tiger_mac.py            # 或你自己的 agent 应用
# capability_service.py 注册了对端发来的命令处理（@search → 本地检索 → 加密回传）
```

**客户端/请求端**（想借用对端资源的那台）：
```bash
export AGENTLINK_PEER_HTTP="http://<执行端IP>:18799" \
       AGENTLINK_PEER_WS="ws://<执行端IP>:18799/agentlink/ws" \
       AGENTLINK_PEER_DID="did:agentlink:<执行端>" \
       AGENTLINK_MY_KEY="~/.agentlink/my.key.json" \
       AGENTLINK_MY_IP="<本机IP>"
python send_interactive.py
# 出现提示符后输入：
#   @search <关键词>   → 加密请求对端搜索其本地素材库，结果加密回传并解密显示
#   其他任意文字      → 作为普通加密消息发送
```

> 所有机器信息（密钥路径 / IP / DID）均通过环境变量配置，不硬编码，便于安全分发，避免泄漏局域网拓扑。

### 联调暴露并修复的 5 个协议缺陷

详见 [`CHANGELOG.md`](CHANGELOG.md)。一句话——本地自测通过 ≠ 跨机能跑：E2EE 是 P2P 对称协商，任何一侧实现不一致（坏 import、上下文未写入、🔒 前缀未剥离、占位符 DID、async 未 await）都会在跨机握手时暴露。**补丁必须两侧同步，否则不对称即失败。**

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
