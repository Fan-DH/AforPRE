# -*- coding: utf-8 -*-
"""gdb 引擎的 Provider 主管。

对外暴露统一操作接口（操作名 = 工具名，前缀 gdb_），内部把每个操作委托给
细分模块：lifecycle（会话生命周期）、control（执行控制）、data（状态与数据）、
breakpoints（断点/线程/设置）、mapping（地址互译）。
生命周期：调试会话是独立 gdb 进程，在工具调用与 MCP 重启之间保持存活；
本 Provider 只做探测与 RPC，不缓存 gdb 路径（每次按当前环境探测）。
"""

from __future__ import annotations

from config import Config
from contracts.results import ToolResult
from tools.gdb import breakpoints, control, data, lifecycle, mapping
from tools.gdb.config import probe_environment


class GdbProvider:
    def __init__(self, config: Config):
        self.config = config

    def check_environment(self) -> dict:
        """当前运行态检查：gdb 探测每次实时执行，无缓存失效问题。"""
        state = probe_environment()
        return {
            **state,
            "detected_available": state["available"],
            "available": state["available"],
            "runtime": {
                "available": state["available"],
                "restart_required": False,
                "reason": "ready" if state["available"] else "environment_unavailable",
                "gdb_path": state["gdb_path"],
            },
        }

    # --- 会话生命周期 ---
    def gdb_launch(self, args: dict) -> ToolResult:
        return lifecycle.gdb_launch(self, args)

    def gdb_attach(self, args: dict) -> ToolResult:
        return lifecycle.gdb_attach(self, args)

    def gdb_connect(self, args: dict) -> ToolResult:
        return lifecycle.gdb_connect(self, args)

    def gdb_sessions(self, args: dict) -> ToolResult:
        return lifecycle.gdb_sessions(self, args)

    def gdb_kill(self, args: dict) -> ToolResult:
        return lifecycle.gdb_kill(self, args)

    def gdb_detach(self, args: dict) -> ToolResult:
        return lifecycle.gdb_detach(self, args)

    # --- 执行控制 ---
    def gdb_continue(self, args: dict) -> ToolResult:
        return control.gdb_continue(self, args)

    def gdb_interrupt(self, args: dict) -> ToolResult:
        return control.gdb_interrupt(self, args)

    def gdb_step(self, args: dict) -> ToolResult:
        return control.gdb_step(self, args)

    def gdb_trace(self, args: dict) -> ToolResult:
        return control.gdb_trace(self, args)

    # --- 状态与数据 ---
    def gdb_state(self, args: dict) -> ToolResult:
        return data.gdb_state(self, args)

    def gdb_output(self, args: dict) -> ToolResult:
        return data.gdb_output(self, args)

    def gdb_send_input(self, args: dict) -> ToolResult:
        return data.gdb_send_input(self, args)

    def gdb_registers(self, args: dict) -> ToolResult:
        return data.gdb_registers(self, args)

    def gdb_memory_read(self, args: dict) -> ToolResult:
        return data.gdb_memory_read(self, args)

    def gdb_memory_dump(self, args: dict) -> ToolResult:
        return data.gdb_memory_dump(self, args)

    def gdb_tracee_read(self, args: dict) -> ToolResult:
        return data.gdb_tracee_read(self, args)

    def gdb_read_struct(self, args: dict) -> ToolResult:
        return data.gdb_read_struct(self, args)

    def gdb_memory_write(self, args: dict) -> ToolResult:
        return data.gdb_memory_write(self, args)

    def gdb_memory_search(self, args: dict) -> ToolResult:
        return data.gdb_memory_search(self, args)

    def gdb_backtrace(self, args: dict) -> ToolResult:
        return data.gdb_backtrace(self, args)

    def gdb_disassemble(self, args: dict) -> ToolResult:
        return data.gdb_disassemble(self, args)

    def gdb_evaluate(self, args: dict) -> ToolResult:
        return data.gdb_evaluate(self, args)

    # --- 断点 / 线程 / 设置 ---
    def gdb_breakpoint(self, args: dict) -> ToolResult:
        return breakpoints.gdb_breakpoint(self, args)

    def gdb_thread(self, args: dict) -> ToolResult:
        return breakpoints.gdb_thread(self, args)

    def gdb_set(self, args: dict) -> ToolResult:
        return breakpoints.gdb_set(self, args)

    def gdb_handle_signal(self, args: dict) -> ToolResult:
        return breakpoints.gdb_handle_signal(self, args)

    # --- 地址互译 ---
    def gdb_map_address(self, args: dict) -> ToolResult:
        return mapping.gdb_map_address(self, args)
