# -*- coding: utf-8 -*-
"""gdb 引擎的执行控制操作：continue / interrupt / step。"""

from __future__ import annotations

from contracts.results import ToolResult
from tools.base import ProviderError
from tools.gdb import session
from tools.gdb.common import (GENERAL_LIMITATIONS, SOFTWARE_BREAKPOINT_LIMITATION, result,
                              run_with_interrupt_on_timeout, session_dir)


def gdb_continue(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    timeout = args.get("timeout") or session.continue_timeout()
    data = run_with_interrupt_on_timeout(provider, session_id, "continue", {}, timeout)
    return result(data, limitations=list(GENERAL_LIMITATIONS))


def gdb_interrupt(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    session_dir(provider, session_id)
    data = session.interrupt_and_wait(provider.config.workspace, session_id)
    return result(data, limitations=list(GENERAL_LIMITATIONS) + [
        "SIGINT 会传递给目标进程；若程序自行处理该信号，停止行为取决于程序。"])


def gdb_step(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    action = args.get("action", "step_instruction")
    params = {"action": action}
    if action == "run_until":
        if not args.get("address"):
            raise ProviderError("run_until 需要 address 参数",
                                limitations=["没有执行单步操作。"])
        params["address"] = args["address"]
    # Even a source step can enter a blocking read or a long-running callee.
    data = run_with_interrupt_on_timeout(provider, session_id, "step", params,
                                         session.continue_timeout())
    limitations = list(GENERAL_LIMITATIONS)
    if action in ("run_until", "next_line", "next_instruction", "finish"):
        limitations.append("该操作可能使用临时软件断点。" + SOFTWARE_BREAKPOINT_LIMITATION)
    return result(data, limitations=limitations)


def gdb_trace(provider, args: dict) -> ToolResult:
    from tools.gdb.artifacts import artifact_directory
    if ('memory_address' in args) != ('memory_length' in args):
        raise ProviderError('memory_address 和 memory_length 必须同时提供')
    session_dir(provider, args['session_id'])
    directory = artifact_directory(provider.config.workspace, 'trace')
    params = {key: value for key, value in args.items() if key != 'session_id'}
    params['artifact_dir'] = str(directory)
    timeout = args.get('timeout', 10)
    # The bridge owns the deadline so it can persist partial results before replying.
    data = run_with_interrupt_on_timeout(provider, args['session_id'], 'trace', params, timeout + 10)
    data.setdefault('path', str(directory / 'trace.jsonl'))
    limitations = ['跟踪只记录每次操作后的停止点；next_instruction 会越过调用，continue 不记录停止点之间的指令。',
                   '信号传递遵循当前 GDB handle 设置；continue_signals 仅控制是否继续采集。']
    if args.get('memory_address') or args.get('action') == 'next_instruction':
        limitations.append(SOFTWARE_BREAKPOINT_LIMITATION)
    if data.get('termination') == 'error' or data.get('interrupted_after_timeout'):
        return ToolResult(status='timeout' if data.get('interrupted_after_timeout') else 'error',
                      error=data.get('error') or '跟踪 RPC 超时', data=data,
                      limitations=limitations + ['跟踪未完成，文件可能仅包含部分记录。'],
                      diagnostics=[{'code': 'gdb.trace_partial', 'severity': 'error',
                                    'message': data.get('error') or '跟踪 RPC 超时', 'details': {}, 'suggestions': []}])
    return result(data, limitations=limitations)
