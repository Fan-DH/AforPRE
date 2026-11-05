# -*- coding: utf-8 -*-
"""gdb 引擎操作的共享辅助：会话定位、RPC、结果构造与长操作超时处理。"""

from __future__ import annotations

import os

from contracts.results import TIMEOUT, ToolResult
from tools.base import ProviderError
from tools.gdb import probe, session

GENERAL_LIMITATIONS = [
    "动态调试结果只反映当前停止时刻的快照；继续执行后必须重新查询。",
    "目标进程的输入只能在停止状态下写入（数据缓存在 PTY 中，由程序后续读取）。",
    "会话由独立 gdb 进程承载：MCP 服务重启不结束会话，用 gdb_sessions 查看。",
]

SOFTWARE_BREAKPOINT_LIMITATION = (
    "软件断点通常会改写目标指令（x86 常见为 0xCC），移除时可能还原保存的旧字节；"
    "在目标自行修改或校验的代码区可能干扰执行。GDB 内存读取还可能隐藏断点替换字节，"
    "回读一致不能排除此影响。此类位置可用 type=hardware 或在不变的外围代码处停止；"
    "硬件断点数量和支持取决于目标，已受影响的字节不会因此自动恢复。"
)


def debugger_probe() -> dict:
    state = probe.probe_debugger()
    if not state["available"]:
        raise ProviderError(
            "动态调试不可用：%s" % (state["error"] or "gdb 缺失"),
            limitations=["没有启动或操作调试会话；目标程序没有被调试。"],
            diagnostics=[{"code": "gdb.unavailable", "severity": "error",
                          "message": state["error"] or "gdb 缺失",
                          "details": {key: state[key] for key in (
                              "gdb_path", "version", "python_version", "reason")},
                          "suggestions": [state["install_hint"]]}],
        )
    return state


def session_dir(provider, session_id: str) -> str:
    return session.session_dir(provider.config.workspace, session_id)


def rpc(provider, session_id: str, op: str, params: dict | None = None,
        timeout: int | None = None) -> dict:
    return session.rpc(provider.config.workspace, session_id, op, params, timeout)


def result(data, limitations=None, diagnostics=None) -> ToolResult:
    return ToolResult(data=data, limitations=list(limitations or []),
                      diagnostics=list(diagnostics or []))


def require_file(path: str) -> str:
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise ProviderError("目标不存在或不是文件: %s" % path, status="not_found",
                            limitations=["没有创建调试会话；目标程序没有被加载。"])
    return path


def run_with_interrupt_on_timeout(provider, session_id: str, op: str, params: dict,
                                  timeout: int) -> dict:
    """执行可能长时间运行的 op；超时后 SIGINT 中断并返回中断后的状态。"""
    try:
        return rpc(provider, session_id, op, params, timeout=timeout)
    except ProviderError as exc:
        codes = [item.get("code") for item in exc.diagnostics]
        if exc.status != TIMEOUT or "gdb.rpc_timeout" not in codes:
            raise
        state = session.interrupt_and_wait(provider.config.workspace, session_id)
        state["interrupted_after_timeout"] = True
        state["timeout_seconds"] = timeout
        state["interruption"] = "目标进程超过 %ss 未停止，已自动发送 SIGINT 中断；会话保持可用。" % timeout
        return state
