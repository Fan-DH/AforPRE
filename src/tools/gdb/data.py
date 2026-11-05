# -*- coding: utf-8 -*-
"""gdb 引擎的状态与数据读取操作：state/output/input/registers/memory/backtrace/disassemble/evaluate。"""

from __future__ import annotations

import re

from contracts.results import ToolResult
from tools.gdb import session
from tools.gdb.common import GENERAL_LIMITATIONS, result, rpc, run_with_interrupt_on_timeout
from tools.gdb.diagnostics import error


def gdb_state(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    data = rpc(provider, session_id, "state", {})
    meta = session.read_session_state(provider.config.workspace, session_id)
    data.setdefault("mode", meta.get("mode"))
    data.setdefault("target", meta.get("target"))
    data.setdefault("stop_at", meta.get("stop_at"))
    data.setdefault("effective_stop_at", meta.get("effective_stop_at"))
    data.setdefault("warnings", meta.get("warnings", []))
    data["gdb_pid"] = meta.get("gdb_pid")
    data["last_activity"] = meta.get("last_activity")
    return result(data, limitations=list(GENERAL_LIMITATIONS))


def gdb_output(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    data = rpc(provider, session_id, "output", {})
    return result(data, limitations=[
        "输出经 PTY 捕获；程序未换行刷新的内容可能延迟到缓冲区刷新或停止时才可见。",
        "单次返回最多 1MB；更长输出分多次调用读取（truncated=true 表示还有剩余）。",
    ])


def gdb_send_input(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    data = rpc(provider, session_id, "input", {"data": args["data"]})
    limitations = list(GENERAL_LIMITATIONS) + [
        "输入只在停止状态下写入 PTY 缓冲区；若进程正在等待输入，应先让它停在读取点再写入。",
        "输入是原始字节流；需要换行结束时请在 data 末尾包含 \\n。",
    ]
    if data.get("complete") is False:
        limitations.append("PTY 只接受了 %s/%s 字节；剩余输入未送达，请分批发送。" % (data["written"], data["requested"]))
    return result(data, limitations=limitations)


def gdb_registers(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    data = rpc(provider, session_id, "registers",
               {"names": list(args.get("names") or []), "all": bool(args.get("all"))})
    failed = [reg for reg in data.get("registers", []) if reg.get("error")]
    limitations = list(GENERAL_LIMITATIONS)
    if failed:
        limitations.append("部分寄存器读取失败: %s；error 字段给出原因，不表示其他寄存器无效。"
                           % ", ".join(reg["name"] for reg in failed))
    return result(data, limitations=limitations)


def gdb_memory_read(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    data = rpc(provider, session_id, "memory_read",
               {"address": args["address"], "length": args.get("length", 16)})
    limitations = list(GENERAL_LIMITATIONS)
    if data.get("actual_length") != data.get("requested_length"):
        limitations.append("短读：请求 %s 字节，实际可读 %s 字节；未用零填充伪造结果。"
                           % (data.get("requested_length"), data.get("actual_length")))
    return result(data, limitations=limitations)


def gdb_memory_write(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    data = rpc(provider, session_id, "memory_write",
               {"address": args["address"], "bytes": list(args["bytes"])})
    limitations = list(GENERAL_LIMITATIONS) + [
        "运行时 patch 只作用于进程内存，不修改磁盘文件；进程重启后失效。"]
    if not data.get("verified"):
        limitations.append("回读校验未确认写入内容与原值一致（readback_error: %s）。"
                           % data.get("readback_error"))
    return result(data, limitations=limitations)


def gdb_memory_search(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    data = rpc(provider, session_id, "memory_search", {
        "start": args["start"], "length": args["length"],
        "pattern": [int(v) for v in args["pattern"]],
        "max_hits": args.get("max_hits", 100),
    })
    limitations = list(GENERAL_LIMITATIONS)
    if data.get("truncated"):
        limitations.append("命中数超过 max_hits，结果已截断。")
    if data.get("warnings"):
        limitations.append("搜索过程有警告（可能跨越未映射内存）: %s" % data["warnings"])
    return result(data, limitations=limitations)


def gdb_backtrace(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    data = rpc(provider, session_id, "backtrace", {"depth": args.get("depth", 20)})
    limitations = list(GENERAL_LIMITATIONS) + [
        "无符号的帧没有函数名；栈回溯可能被反调试手段破坏，不保证覆盖真实调用链。"]
    return result(data, limitations=limitations)


def gdb_disassemble(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    params = {"count": args.get("count", 16)}
    if args.get("address"):
        params["address"] = args["address"]
    data = rpc(provider, session_id, "disassemble", params)
    limitations = list(GENERAL_LIMITATIONS) + [
        "指令长度由目标架构解码器给出；bytes_hex 为空表示该处字节不可读。"]
    return result(data, limitations=limitations)


def gdb_evaluate(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    expression = args["expression"]
    # Only recognize unambiguous CLI syntax; names such as x/40 and call(3)
    # are valid C expressions and must reach GDB unchanged.
    if re.match(r"^\s*(?:x|examine)/[0-9]+[bhwg][A-Za-z]*\s+\S", expression):
        raise error("gdb.expression_required",
                    "gdb_evaluate 仅支持表达式；x/... 是 GDB 命令，请用 gdb_memory_read。",
                    details={"expression": expression},
                    suggestions=["例如 gdb_memory_read(address='$rbp-0x30', length=40)。"],
                    limitations=["命令未执行；没有读取或修改目标内存。"])
    if re.match(r"^\s*(?:call|print|p)\s+[A-Za-z_$][\w$]*\s*\(", expression):
        raise error("gdb.expression_required",
                    "gdb_evaluate 仅支持表达式；函数调用请传 fn(args)，不要加 call/print 前缀。",
                    details={"expression": expression},
                    suggestions=["有类型符号：fun(3)；无类型符号：((int (*)(int))0xADDRESS)(3)，类型须符合目标 ABI。"],
                    limitations=["命令未执行；没有调用目标函数。"])
    data = run_with_interrupt_on_timeout(provider, session_id, "evaluate", {"expression": expression},
                                         args.get("timeout") or session.rpc_timeout())
    if data.get("interrupted_after_timeout"):
        raise error("gdb.evaluate_timeout", "表达式求值超时，已发送中断；未获得返回值。",
                    status="timeout", data=data, details={"expression": expression},
                    limitations=["函数可能已经产生副作用；中断不会回滚内存或外部操作。"],
                    suggestions=["用 gdb_state 和 gdb_backtrace 核对停止位置，不要自动重试函数调用。"])
    limitations = list(GENERAL_LIMITATIONS) + [
        "含函数调用的表达式会在目标进程内执行代码，可能改变进程状态甚至使其崩溃。",
        "string 字段只在表达式为字符指针/数组时尝试解析，最长 512 字符。"]
    return result(data, limitations=limitations)


def gdb_memory_dump(provider, args: dict) -> ToolResult:
    import hashlib
    from tools.gdb.artifacts import artifact_directory
    data = rpc(provider, args['session_id'], 'memory_snapshot', {
        'address': args['address'], 'length': args['length'], 'explicit_destination': True})
    raw = bytes.fromhex(data.pop('bytes_hex'))
    data.pop('ascii', None)
    if len(raw) != args['length']:
        raise error('gdb.dump_short_read', '内存导出未获得请求的全部字节，未生成文件。', data=data)
    path = artifact_directory(provider.config.workspace, 'memory') / 'memory.bin'
    path.write_bytes(raw)
    data.update(path=str(path), sha256=hashlib.sha256(raw).hexdigest(), format='binary')
    from tools.gdb.common import SOFTWARE_BREAKPOINT_LIMITATION
    return result(data, limitations=[SOFTWARE_BREAKPOINT_LIMITATION])



def gdb_tracee_read(provider, args):
    payload = rpc(provider, args['session_id'], 'tracee_read',
                  {key: args[key] for key in ('pid', 'address', 'length')})
    return result(payload, limitations=['读取受本地内核 /proc 权限限制；不支持远程目标，不会抢占 tracer。',
        '校验指定线程的停止状态；其他线程或共享映射写入者仍可能改变内存。返回原始内存，不应用 GDB 软件断点字节隐藏。'])


def gdb_read_struct(provider, args):
    payload = rpc(provider, args['session_id'], 'read_struct',
                  {key: args[key] for key in ('address', 'layout')})
    return result(payload, limitations=['这是调用者指定位置的已保存结构体；布局解释不证明数据来自成功的 PTRACE_GETREGS，也不证明仍为子进程当前寄存器。'])
