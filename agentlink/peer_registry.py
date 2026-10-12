"""
AgentLink 对端登记表加载器（T4，2026-10-12）
=============================================
统一读取 `agentlink_peers.json`，解析 lan / tailnet 两类对端。

解决：各脚本（agentlink_call_zheng/tiger、T1 connect、T3 回归）原先各自读 json、
各自硬编码兜底值 → 分散、易漂。集中到本模块。

对端 schema（agentlink_peers.json）：
  {
    "_my_name": "tiger-mac",
    "peers": {
      "<name>": {
        "http": "http://host:port",
        "ws":   "ws://host:port/agentlink/ws",
        "did":  "did:agentlink:...",
        "host": "host-or-ip",
        "net":  "lan" | "tailnet",     # tailnet=走 Tailscale
        ...
      }
    }
  }

环境变量覆盖（优先级最高）：AL_TARGET / AL_TARGET_WS / AL_TARGET_DID
"""
from __future__ import annotations

import json
import os

__all__ = ["load_registry", "get_peer", "resolve_peer", "list_peers"]

_DEFAULT_REGISTRY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "agentlink_peers.json",
)


def load_registry(path: str | None = None) -> dict:
    """加载登记表。找不到/损坏 → 返回空结构（不抛，调用方按空处理）。"""
    candidates = [path] if path else [
        _DEFAULT_REGISTRY,
        os.path.join(os.getcwd(), "agentlink_peers.json"),
        "/tmp/agentlink_peers.json",
    ]
    for p in candidates:
        if p and os.path.exists(p):
            try:
                return json.load(open(p, encoding="utf-8"))
            except Exception:  # noqa: BLE001
                continue
    return {"peers": {}}


def list_peers(path: str | None = None) -> list[str]:
    return sorted(load_registry(path).get("peers", {}).keys())


def get_peer(name: str, path: str | None = None) -> dict:
    """取单个对端登记项（原始 dict，未解析）。找不到 → 空 dict。"""
    return load_registry(path).get("peers", {}).get(name, {}) or {}


def resolve_peer(name: str, path: str | None = None) -> dict:
    """解析对端为可直接使用的连接参数。

    返回 dict(http, ws, did, host, net)，环境变量 AL_TARGET* 可覆盖。
    对 tailnet 对端：优先用 MagicDNS 名/100.x；对 lan 对端：保持主机名。
    IPv4 解析（D3）由调用方按需再做（跨网 tailnet 不需要 IPv4 强制）。
    """
    p = get_peer(name, path)
    http = os.environ.get("AL_TARGET") or p.get("http", "")
    ws = os.environ.get("AL_TARGET_WS") or p.get("ws", "")
    did = os.environ.get("AL_TARGET_DID") or p.get("did", "")
    return {
        "name": name,
        "http": http,
        "ws": ws,
        "did": did,
        "host": p.get("host", ""),
        "net": p.get("net", "lan"),
        "ssh_user": p.get("ssh_user", ""),
        "note": p.get("note", ""),
    }
