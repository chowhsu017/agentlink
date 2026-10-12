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

__all__ = ["prefer_ipv4_url", "resolve_ipv4", "prefer_ipv4_host", "detect_tailnet_ip"]


def _debug(msg: str):
    if os.environ.get("AL_NET_DEBUG"):
        print(f"  [netutil] {msg}")


def detect_tailnet_ip() -> str | None:
    """探测本机 Tailscale (tailnet) 的 100.x.y.z 地址。

    用途：让 agentlink serve 只绑 tailnet 接口（不暴露给同网段/公网）——
    对应《家庭多机场景整合设计》§4 的"服务只 bind tailnet 接口"要求。

    探测顺序（稳 → 脆）：
      1. 环境变量 AL_TAILNET_IP（显式指定，最高优先）
      2. `tailscale ip -4`（官方/Headscale 客户端都有）
      3. 遍历本机网卡，找 100.64.0.0/10（CGNAT 段，Tailscale 专用）的 IPv4
    返回 None = 未检测到（Tailscale 未装/未登录）→ 调用方应报错而非静默绑 0.0.0.0。
    """
    # 1. 显式环境变量
    env_ip = os.environ.get("AL_TAILNET_IP")
    if env_ip:
        _debug(f"AL_TAILNET_IP={env_ip}")
        return env_ip
    # 2. tailscale ip -4
    import subprocess
    for cmd in (["tailscale", "ip", "-4"],
                ["/Applications/Tailscale.app/Contents/MacOS/Tailscale", "ip", "-4"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                ip = r.stdout.strip().splitlines()[0].strip()
                _debug(f"{' '.join(cmd)} -> {ip}")
                return ip
        except Exception as e:  # noqa: BLE001
            _debug(f"{' '.join(cmd)} 失败: {e}")
    # 3. 网卡扫描：100.64.0.0/10
    try:
        import socket as _s
        hostname = _s.gethostname()
        for info in _s.getaddrinfo(hostname, None, family=_s.AF_INET):
            ip = info[4][0]
            octets = ip.split(".")
            if len(octets) == 4 and octets[0] == "100":
                try:
                    second = int(octets[1])
                    if 64 <= second <= 127:  # 100.64.0.0/10
                        _debug(f"网卡扫描命中 tailnet: {ip}")
                        return ip
                except ValueError:
                    pass
    except Exception as e:  # noqa: BLE001
        _debug(f"网卡扫描失败: {e}")
    return None


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
