# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""获取调用图。

无参数时返回全程序调用边；提供 address/name 时返回单函数的 callees + callers
（与 xrefs_from 等价，此处保留以独立调用）。

参数（可选）：
  address: 函数入口地址
  name: 函数名
"""

from _common import parse_args, emit_result, fail, resolve_function

params = parse_args(getScriptArgs())
prog = currentProgram
fm = prog.getFunctionManager()

addr_str = params.get("address")
name = params.get("name")

if addr_str or name:
    func = resolve_function(prog, params, toAddr)
    if func is None:
        fail(u"未找到函数: address=%s name=%s" % (addr_str, name))
    else:
        callees = []
        for c in func.getCalledFunctions(monitor):
            callees.append({"address": str(c.getEntryPoint()), "name": c.getName()})
        callers = []
        for c in func.getCallingFunctions(monitor):
            callers.append({"address": str(c.getEntryPoint()), "name": c.getName()})
        emit_result({
            "function": func.getName(),
            "address": str(func.getEntryPoint()),
            "callees": callees,
            "callers": callers,
        })
else:
    edges = []
    for f in fm.getFunctions(True):
        src = str(f.getEntryPoint())
        src_name = f.getName()
        for c in f.getCalledFunctions(monitor):
            edges.append({
                "from": src,
                "from_name": src_name,
                "to": str(c.getEntryPoint()),
                "to_name": c.getName(),
            })
    emit_result({"edges": edges, "count": len(edges)})
