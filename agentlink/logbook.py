"""
AgentLink 日志助手（v0.3.1 P1-1）
==================================
背景：v0.3.0 全仓 82 处 `except: pass`，关键路径（解密/账本/审计）失败全静默
→ 系统在「未知状态」继续跑。P1-1 把这些换成**结构化日志**。

原则：
  · **不阻断主链路**（通信不能因审计/账本失败而挂）——但**必须留痕**
  · 分级：debug/info/warning/error；关键路径失败用 warning 以上
  · 可用环境变量控制：AGENTLINK_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR（默认 WARNING）
  · AGENTLINK_LOG_FILE 可指定输出文件；不设则输出到 stderr

用法：
    from .logbook import log
    log.warn("ledger", "记帧失败", session=self.session_id, exc=e)
"""
from __future__ import annotations

import logging
import os
import sys

_LOGGER_NAME = "agentlink"

_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}


def _build_logger() -> logging.Logger:
    lg = logging.getLogger(_LOGGER_NAME)
    if lg.handlers:  # 幂等：已配置则不重复加 handler
        return lg
    level = _LEVELS.get(os.environ.get("AGENTLINK_LOG_LEVEL", "WARNING").upper(),
                        logging.WARNING)
    lg.setLevel(level)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] agentlink.%(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    log_file = os.environ.get("AGENTLINK_LOG_FILE", "")
    if log_file:
        try:
            h = logging.FileHandler(log_file, encoding="utf-8")
        except Exception:  # noqa: BLE001
            h = logging.StreamHandler(sys.stderr)
    else:
        h = logging.StreamHandler(sys.stderr)
    h.setFormatter(fmt)
    lg.addHandler(h)
    lg.propagate = False
    return lg


class _Log:
    """薄封装：给每条日志带上「模块」前缀与结构化 kwargs。"""

    def __init__(self):
        self._lg = _build_logger()

    def _emit(self, level: int, mod: str, msg: str, exc: BaseException | None = None, **kw):
        extra = ""
        if kw:
            extra = " " + " ".join(f"{k}={v!r}" for k, v in kw.items())
        if exc is not None:
            extra += f" | exc={type(exc).__name__}: {exc}"
        self._lg.log(level, f"[{mod}] {msg}{extra}")

    def debug(self, mod: str, msg: str, exc=None, **kw):
        self._emit(logging.DEBUG, mod, msg, exc, **kw)

    def info(self, mod: str, msg: str, exc=None, **kw):
        self._emit(logging.INFO, mod, msg, exc, **kw)

    def warn(self, mod: str, msg: str, exc=None, **kw):
        self._emit(logging.WARNING, mod, msg, exc, **kw)

    def error(self, mod: str, msg: str, exc=None, **kw):
        self._emit(logging.ERROR, mod, msg, exc, **kw)


log = _Log()
