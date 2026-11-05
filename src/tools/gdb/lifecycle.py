# -*- coding: utf-8 -*-
"""gdb 引擎的会话生命周期操作：launch / attach / connect / sessions / kill / detach。"""

from __future__ import annotations

import os

from contracts.results import ToolResult
from tools.gdb import session
from tools.gdb.timers import probe_timers
from tools.gdb.common import (GENERAL_LIMITATIONS, debugger_probe, require_file,
                              result, session_dir)
from tools.gdb.diagnostics import diagnostic, error


def gdb_launch(provider, args: dict) -> ToolResult:
    debugger_probe()
    target = require_file(args["target_path"])
    cwd = args.get("cwd")
    if cwd is not None:
        if any(c in cwd for c in "\x00\r\n"):
            raise error("gdb.invalid_cwd", "cwd 不能包含换行或 NUL")
        cwd = os.path.abspath(cwd)
        if not os.path.isdir(cwd):
            raise error("gdb.invalid_cwd", "cwd 不存在或不是目录: %s" % cwd,
                        details={"cwd": cwd}, suggestions=["传入存在的目录；不要在路径字符串外额外添加引号。"])
    timers = probe_timers(target)
    state = session.start_session(provider.config.workspace, {
        "alarm_policy": args.get("alarm_policy", "default"),
        "mode": "launch",
        "target": target,
        "args": list(args.get("args") or []),
        "env": dict(args.get("env") or {}),
        "cwd": cwd,
        "stop_at": args.get("stop_at", "entry"),
    })
    directory = session_dir(provider, state.get("session_id"))
    diagnostics = []
    if timers['symbols']:
        diagnostics.append(diagnostic('gdb.timer_imports', '目标导入定时器 API；调试暂停可能跨过墙钟期限，但导入不证明已设置定时器。',
            details=timers, suggestions=['需要递送前停下可用 alarm_policy=stop；明确允许改变行为才用 ignore（不递送 SIGALRM）。']))
    if not timers['checked']:
        diagnostics.append(diagnostic('gdb.timer_probe_unavailable', '未完成定时器导入检查，不能推断目标没有定时器。', details=timers))
    return result({
        "session_id": state.get("session_id"),
        "state": state.get("state"),
        "stop": state.get("stop"),
        "exit_code": state.get("exit_code"),
        "target": target,
        "mode": "launch",
        "stop_at": args.get("stop_at", "entry"),
        "gdb_pid": state.get("gdb_pid"),
        "inferior_pid": state.get("inferior_pid"),
        "effective_stop_at": state.get("effective_stop_at"),
        "gdb_log_path": os.path.join(directory, session.GDB_LOG),
        "output_log_path": os.path.join(directory, session.OUTPUT_LOG),
        "warnings": state.get("startup_warnings", []) + state.get("warnings", []),
        "cwd": cwd,
        "timer_probe": timers,
        "alarm_policy": args.get("alarm_policy", "default"),
    }, diagnostics=diagnostics, limitations=GENERAL_LIMITATIONS + [
        "alarm_policy=ignore 仅抑制 SIGALRM 递送，会改变程序行为；不取消定时器，也不覆盖 SIGVTALRM/SIGPROF。",
        "gdb 默认关闭 ASLR（disable-randomization on）；确需 ASLR 时用 gdb_set 打开。",
        "stop_at=entry 停在程序入口指令（PIE 自动换算运行时入口；换算失败时退回首条指令停点）；"
        "无 main 符号时 stop_at=main 自动退回入口。",
    ])


def gdb_attach(provider, args: dict) -> ToolResult:
    probe_state = debugger_probe()
    target = None
    if args.get("target_path"):
        target = require_file(args["target_path"])
    state = session.start_session(provider.config.workspace, {
        "mode": "attach",
        "pid": int(args["pid"]),
        "target": target,
    })
    limitations = list(GENERAL_LIMITATIONS)
    if probe_state.get("ptrace_scope") not in (0, None):
        limitations.append("内核 ptrace 限制：%s" % probe_state.get("attach_note"))
    return result({
        "session_id": state.get("session_id"),
        "state": state.get("state"),
        "pid": args["pid"],
        "mode": "attach",
        "gdb_pid": state.get("gdb_pid"),
        "inferior_pid": state.get("inferior_pid"),
        "gdb_log_path": os.path.join(session_dir(provider, state.get("session_id")),
                                     session.GDB_LOG),
    }, limitations=limitations)


def gdb_connect(provider, args: dict) -> ToolResult:
    debugger_probe()
    target = None
    if args.get("target_path"):
        target = require_file(args["target_path"])
    state = session.start_session(provider.config.workspace, {
        "mode": "remote",
        "host": args["host"],
        "port": int(args["port"]),
        "target": target,
    })
    return result({
        "session_id": state.get("session_id"),
        "state": state.get("state"),
        "host": args["host"],
        "port": args["port"],
        "mode": "remote",
        "gdb_pid": state.get("gdb_pid"),
        "inferior_pid": state.get("inferior_pid"),
        "gdb_log_path": os.path.join(session_dir(provider, state.get("session_id")),
                                     session.GDB_LOG),
    }, limitations=GENERAL_LIMITATIONS + [
        "远端目标无法读取本地进程映射（/proc），gdb_map_address 对该会话不可用。",
    ])


def gdb_sessions(provider, args: dict) -> ToolResult:
    data = session.list_sessions(provider.config.workspace, args.get('reap_exited', False))
    return result(data, limitations=[
        'gdb_alive/process_alive 表示调试器存活；inferior_alive 表示选中目标存活，can_control 表示可进行停止态操作。',
        'exited 默认保留输出且不可继续执行；reap_exited=true 可关闭并归档，无存活 inferior 才回收。',
        '这是瞬时探测；busy 时不会把连接 socket 当成响应成功。'])


def gdb_kill(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    session_dir(provider, session_id)  # 会话不存在时报 not_found
    before = session.read_session_state(provider.config.workspace, session_id)
    closed = session.close_session(provider.config.workspace, session_id)
    if not closed.get("closed"):
        raise error("gdb.close_unconfirmed", "调试器退出未确认，保留会话目录以便恢复和诊断。",
                    details=closed, limitations=["没有删除会话目录；目标是否终止请通过 gdb_sessions 核对。"])
    cleaned = session.cleanup_session_dir(provider.config.workspace, session_id)
    return result({
        "session_id": session_id,
        "final_state": before.get("state"),
        "stop": before.get("stop"),
        "exit_code": before.get("exit_code"),
        "closed": closed.get("closed", False),
        "force_killed": closed.get("force_killed", False),
        "cleaned": cleaned,
    }, limitations=["会话目录已清理，日志与输出不可再读取；需要留存信息时先调用 state/output。"],
       diagnostics=[diagnostic("gdb.session_closed",
                               "调试会话 %s 已终止并清理。" % session_id, severity="info",
                               details={"force_killed": closed.get("force_killed"),
                                        "close_error": closed.get("close_error")})])


def gdb_detach(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    session_dir(provider, session_id)
    before = session.read_session_state(provider.config.workspace, session_id)
    data = session.rpc(provider.config.workspace, session_id, "detach", {}, timeout=15)
    session.cleanup_session_dir(provider.config.workspace, session_id)
    return result({
        "session_id": session_id,
        "detached": data.get("detached", False),
        "final_state": before.get("state"),
        "note": "目标进程已脱离调试器继续运行。",
    }, limitations=["分离后无法再查询该进程的调试状态；会话目录已清理。"])
