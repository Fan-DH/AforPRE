# -*- coding: utf-8 -*-
"""gdb 引擎的断点/线程/行为设置操作：breakpoint / thread / set / handle_signal。"""

from __future__ import annotations

import re

from contracts.results import ToolResult
from tools.base import ProviderError
from tools.gdb.common import GENERAL_LIMITATIONS, SOFTWARE_BREAKPOINT_LIMITATION, result, rpc
from tools.gdb.diagnostics import diagnostic


def normalize_location(location):
    text = location.strip()
    if re.fullmatch(r"0[xX][0-9a-fA-F]+|[0-9]+", text):
        value = int(text, 16 if text.lower().startswith('0x') else 10)
        return '*0x%x' % value
    return text


def gdb_breakpoint(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    action = args.get("action", "list")
    if action == "set":
        params = {"type": args.get("type", "software"),
                  "temporary": bool(args.get("temporary")),
                  "condition": args.get("condition")}
        if args.get("location"):
            params["location"] = (normalize_location(args["location"])
                                  if params["type"] in ("software", "hardware") else args["location"])
        data = rpc(provider, session_id, "breakpoint_set", params)
    elif action == "remove":
        if not args.get("number") and not args.get("location"):
            raise ProviderError("remove 需要 number 或 location",
                                limitations=["没有删除任何断点。"])
        data = rpc(provider, session_id, "breakpoint_remove",
                   {"number": args.get("number"), "location": args.get("location")})
    elif action == "remove_all":
        data = rpc(provider, session_id, "breakpoint_remove_all", {})
    else:
        data = rpc(provider, session_id, "breakpoint_list", {})
    limitations = list(GENERAL_LIMITATIONS) + [
        "watch_* 的 location 是监视表达式而非地址；catch_* 断点也会出现在 list 中。"]
    diagnostics = []
    if action == "set" and args.get("type", "software") == "software":
        limitations.append(SOFTWARE_BREAKPOINT_LIMITATION)
        diagnostics.append(diagnostic(
            "gdb.software_breakpoint_code_mutation", SOFTWARE_BREAKPOINT_LIMITATION,
            details={"breakpoint": data.get("breakpoint"), "corruption_confirmed": False},
            suggestions=["若该位置会被修改或校验，使用 gdb_breakpoint(type=hardware)，或选择稳定的外围停止点。"]))
    pending = [bp for bp in ([data['breakpoint']] if 'breakpoint' in data else data.get('breakpoints', []))
               if bp.get('pending')]
    if pending:
        message = '断点尚未解析，没有可保证命中的地址；符号加载后可能解析。'
        limitations.append(message)
        diagnostics.append(diagnostic('gdb.breakpoint_pending', message, details={'breakpoints': pending},
            suggestions=['检查地址/符号、模块加载状态和 PIE 地址映射。']))
    return result(data, limitations=limitations, diagnostics=diagnostics)


def gdb_thread(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    action = args.get("action", "list")
    if action == "select":
        if not args.get("thread_id"):
            raise ProviderError("select 需要 thread_id", limitations=["没有切换线程。"])
        data = rpc(provider, session_id, "thread_select",
                   {"thread_id": args["thread_id"]})
    else:
        data = rpc(provider, session_id, "thread_list", {})
    return result(data, limitations=list(GENERAL_LIMITATIONS))


def gdb_set(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    data = rpc(provider, session_id, "set",
               {"setting": args["setting"], "value": args["value"]})
    hints = {
        'disable_randomization': 'disable_randomization 只影响后续 run/start；已运行进程的映射不会变化。',
        'follow_fork_mode': '仅决定后续 fork/vfork 跟随父进程还是子进程；不会重新附加已经分离的子进程。',
        'detach_on_fork': 'off 会让 GDB 保留父子进程控制权；目标自身使用 ptrace 时可能发生 tracer 冲突，不应盲目关闭 detach。',
        'follow_exec_mode': '仅影响后续 exec 的 inferior 管理方式；不会改变已经完成的 exec。',
        'scheduler_locking': '锁定线程调度可能使依赖其他线程的操作阻塞。',
        'stop_on_solib_events': '开启后共享库加载/卸载会增加停止点；这些停止点不一定对应用户断点。',
    }
    return result(data, limitations=[hints[args['setting']]])


def gdb_handle_signal(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    data = rpc(provider, session_id, "handle_signal", {
        "signal": args["signal"], "stop": bool(args.get("stop")),
        "print": bool(args.get("print")),
        "pass_to_program": bool(args.get("pass_to_program", True)),
    })
    return result(data, limitations=list(GENERAL_LIMITATIONS))
