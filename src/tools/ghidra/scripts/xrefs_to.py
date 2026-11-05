# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""查找对某地址的所有引用（含引用类型与所在函数）。

参数：
  address: 目标地址
"""

from _common import parse_args, emit_result, fail

params = parse_args(getScriptArgs())
prog = currentProgram

addr_str = params.get("address")
if not addr_str:
    fail(u"缺少参数: address")
else:
    addr = toAddr(addr_str)
    fm = prog.getFunctionManager()
    refs = prog.getReferenceManager().getReferencesTo(addr)
    xrefs = []
    for ref in refs:
        src = ref.getFromAddress()
        ref_type = ref.getReferenceType().toString()
        func = fm.getFunctionContaining(src)
        func_name = func.getName() if func else ""
        xrefs.append({
            "from_address": str(src),
            "ref_type": ref_type,
            "function": func_name,
            "is_direct": not bool(ref.getReferenceType().isIndirect()),
            "is_read": bool(ref.getReferenceType().isRead()),
            "is_write": bool(ref.getReferenceType().isWrite()),
            "is_call": bool(ref.getReferenceType().isCall()),
        })
    emit_result({"address": addr_str, "xrefs": xrefs, "count": len(xrefs)})
