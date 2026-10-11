"""
D3 修复回归测试 — agentlink.netutil（IPv6/IPv4 双栈兼容）
==========================================================

背景（2026-10-12 实测）：
  · 服务端 uvicorn 绑 0.0.0.0 → 只监听 IPv4
  · macOS 对 .local 主机名 IPv6-first → websockets 首试 IPv6 → 超时
  · 修法：客户端把 host 解析为 IPv4（prefer_ipv4_url）

覆盖：
  · 主机名 → IPv4
  · 已是 IPv4/IPv6 字面量原样保留
  · localhost → 127.0.0.1
  · 解析失败 → 原样返回（不抛）
  · AL_PREFER_IPV6=1 逃生开关
"""

import os
import socket

import pytest

from agentlink.netutil import prefer_ipv4_url, prefer_ipv4_host


def test_hostname_resolves_to_ipv4():
    """本机名可解析 → 换成 IPv4（视环境而定，至少要稳定不变或变成 IP）"""
    url = "ws://localhost:18790/agentlink/ws"
    out = prefer_ipv4_url(url)
    assert out.startswith("ws://127.0.0.1:18790/agentlink/ws")


def test_ipv4_literal_unchanged():
    url = "http://203.0.113.10:18790/x"   # TEST-NET-3（文档用示例段，非真实地址）
    assert prefer_ipv4_url(url) == url


def test_ipv6_literal_unchanged():
    url = "http://[fe80::1]:18790/x"
    assert prefer_ipv4_url(url) == url


def test_unresolvable_host_unchanged():
    """解析失败 → 原样返回（不抛异常）"""
    url = "http://no.such.host.invalid:18790/x"
    assert prefer_ipv4_url(url) == url


def test_non_network_scheme_unchanged():
    assert prefer_ipv4_url("file:///tmp/x") == "file:///tmp/x"


def test_escape_hatch_prefer_ipv6(monkeypatch):
    """AL_PREFER_IPV6=1 → 不强制 IPv4"""
    monkeypatch.setenv("AL_PREFER_IPV6", "1")
    url = "ws://localhost:18790/x"
    # 主机名保留（不被换为 127.0.0.1）
    assert prefer_ipv4_host("localhost", 18790) == "localhost"


def test_real_resolution_when_available():
    """若本机有 hostname，确认能解析出 IPv4（不强制，视环境）"""
    host = socket.gethostname()
    try:
        socket.getaddrinfo(host, 0, family=socket.AF_INET)
        has_v4 = True
    except Exception:
        has_v4 = False
    if has_v4:
        # 不应抛异常
        prefer_ipv4_host(host, 0)
