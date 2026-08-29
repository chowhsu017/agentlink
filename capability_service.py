#!/usr/bin/env python3
"""
AgentLink 能力服务 — tiger-mac 侧的"跨机资源调用"业务层
zheng-mac 加密发来 @search <关键词> → tiger-mac 解密后识别 → 跑本地素材库
→ 结果加密就地回传。

依赖: agentlink_p1 (WS handler 里调用本模块), query.py (素材库检索)
"""
import os, subprocess, json, sys

# 素材库检索脚本
QUERY_PY = os.path.expanduser("~/Desktop/Strong财经/scripts/query.py")
# 结果条数
TOPN = 8


def parse_command(plaintext: str):
    """解析明文是否是要执行的命令。
    返回 (action, args) 或 (None, None) 表示普通聊天/不处理。
    """
    text = plaintext.strip()
    if text.startswith("@search "):
        kw = text[len("@search "):].strip()
        if kw:
            return "search", kw
    elif text == "@search":
        return "search_help", None
    return None, None


def run_query(keyword: str) -> str:
    """执行 query.py 搜索素材库，返回格式化文本结果。失败返回错误信息。"""
    if not os.path.exists(QUERY_PY):
        return f"⚠️ 检索脚本不存在: {QUERY_PY}"
    try:
        proc = subprocess.run(
            [sys.executable, QUERY_PY, keyword, "--top", str(TOPN)],
            capture_output=True, text=True, timeout=30, cwd=os.path.dirname(QUERY_PY),
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if proc.returncode != 0:
            return f"⚠️ query.py 执行出错(code={proc.returncode}): {err[:200]}"
        # 截断过长结果，避免加密帧过大
        if len(out) > 4000:
            out = out[:4000] + "\n…(结果过长已截断)"
        return out if out else f"🔍 未找到与「{keyword}」相关的素材"
    except subprocess.TimeoutExpired:
        return "⚠️ 检索超时(>30s)"
    except Exception as e:
        return f"⚠️ 检索异常: {e}"


def handle(plaintext: str) -> str:
    """处理一条解密后的明文消息，返回要加密回传的响应文本。
    非命令消息返回 None（交给正常流程，不回传）。
    """
    action, arg = parse_command(plaintext)
    if action is None:
        return None

    if action == "search_help":
        return "用法: @search <关键词> —— 搜索 tiger-mac 本地素材库(法条/判例/素材)"

    if action == "search":
        print(f"  🔍 tiger-mac: 收到搜索请求, 关键词=「{arg}」")
        result = run_query(arg)
        # 加个简短回执头，方便 zheng-mac 知道这是搜索结果
        return f"📚 tiger-mac 素材库搜索「{arg}」结果:\n\n{result}"

    return None
