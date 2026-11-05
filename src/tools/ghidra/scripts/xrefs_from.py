# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""查找某函数调用了哪些函数（callee）以及被谁调用（caller）。

参数：
  address: 函数入口地址
  name: 函数名（当 address 未提供时按名查找）
"""

from _common import parse_args, emit_result, fail, resolve_function

params = parse_args(getScriptArgs())
prog = currentProgram
fm = prog.getFunctionManager()

addr_str = params.get("address")
name = params.get("name")

func = resolve_function(prog, params, toAddr)

if func is None:
    fail(u"未找到函数: address=%s name=%s" % (addr_str, name))
else:
    callees = []
    for c in func.getCalledFunctions(monitor):
        callees.append({
            "address": str(c.getEntryPoint()),
            "name": c.getName(),
            "is_thunk": bool(c.isThunk()),
        })
    callers = []
    for c in func.getCallingFunctions(monitor):
        callers.append({
            "address": str(c.getEntryPoint()),
            "name": c.getName(),
        })
    emit_result({
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "callees": callees,
        "callers": callers,
    })
