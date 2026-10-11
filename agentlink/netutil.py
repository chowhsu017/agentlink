"""
AgentLink 网络工具 — IPv6/IPv4 双栈兼容（D3 修复）
=====================================================

问题（2026-10-12 实测确认）：
  · 双端服务端 uvicorn 均绑 `0.0.0.0` → **只监听 IPv4**
  · 但 macOS `getaddrinfo` 对 `.local` 主机名**优先返回 IPv6 (AAAA)**
  · `websockets` 不做 Happy Eyeballs → 首试 IPv6 → 对端无监听 → **超时**（实测 5s 挂死）
  · `httpx` 有 Happy Eyeballs 回退 → 侥幸能连（所以只有 WS 挂）

修复策略（务实）：
  · 本环境 IPv6 互通**不可靠**（ping6 100% 丢包，IPv6 TCP 到监听服务器也超时）
  · 服务端全 IPv4，故**客户端显式选 IPv4** 是最小、最稳、直击根因的修法
  · 集中一个 `prefer_ipv4_url()`，替换各脚本 ad-hoc 的 `_force_ipv4`（防 P-004 静默失效）

逃生开关：
  · `AL_PREFER_IPV6=1` → 强制 IPv6（未来双栈环境可用）
  · `AL_NET_DEBUG=1`   → 打印解析过程
"""

from __future__ import annotations

import os
import socket
import urllib.parse as _up

__all__ = ["prefer_ipv4_url", "resolve_ipv4", "prefer_ipv4_host"]


def _debug(msg: str):
    if os.environ.get("AL_NET_DEBUG"):
        print(f"  [netutil] {msg}")


def resolve_ipv4(host: str, port: int) -> str | None:
    """把主机名解析为**首选 IPv4**地址。返回 None = 解析不到 IPv4。"""
    try:
        infos = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if infos:
            ip = infos[0][4][0]
            _debug(f"resolve_ipv4({host}) -> {ip}")
            return ip
    except Exception as e:  # noqa: BLE001
        _debug(f"resolve_ipv4({host}) 失败: {e}")
    return None


def prefer_ipv4_host(host: str, port: int | None = None) -> str:
    """把裸主机名换成 IPv4（保留原样：已是 IP / 解析不到 / 显式要 IPv6）。"""
    if not host:
        return host
    # 已是 IPv4 字面量
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    # 已是 IPv6 字面量（含冒号）
    if ":" in host:
        return host
    if os.environ.get("AL_PREFER_IPV6"):
        _debug("AL_PREFER_IPV6=1 → 跳过 IPv4 优先")
        return host
    ip4 = resolve_ipv4(host, port or 0)
    return ip4 or host


def prefer_ipv4_url(url: str) -> str:
    """
    把 `scheme://<host>[:port]/path` 里的 host 换成 IPv4（若可解析）。
    只处理 http/https/ws/wss；IPv6 会被 urlsplit 加方括号，此处原样保留。
    """
    try:
        p = _up.urlsplit(url)
        if p.scheme not in ("http", "https", "ws", "wss"):
            return url
        host, port = p.hostname, p.port
        if not host:
            return url
        new_host = prefer_ipv4_host(host, port)
        if new_host == host:
            return url
        # IPv6 字面量需方括号
        netloc_host = f"[{new_host}]" if ":" in new_host else new_host
        netloc = f"{netloc_host}:{port}" if port else netloc_host
        new_url = _up.urlunsplit((p.scheme, netloc, p.path, p.query, p.fragment))
        _debug(f"prefer_ipv4_url: {url} -> {new_url}")
        return new_url
    except Exception as e:  # noqa: BLE001
        _debug(f"prefer_ipv4_url 失败: {e}")
        return url
