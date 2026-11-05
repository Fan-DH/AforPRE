# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""重命名符号（函数或一般符号）。

参数：
  address: 符号所在地址
  new_name: 新名称
"""

from _common import parse_args, emit_result, fail, JAVA_ERRORS, begin_mutation

from ghidra.program.model.symbol import SourceType

params = parse_args(getScriptArgs())
prog = currentProgram

addr_str = params.get("address")
new_name = params.get("new_name")

if not addr_str or not new_name:
    fail(u"缺少参数: address 和 new_name")
else:
    addr = toAddr(addr_str)
    fm = prog.getFunctionManager()

    # 优先处理函数
    func = fm.getFunctionAt(addr)
    if func is not None:
        old_name = func.getName()
        try:
            begin_mutation(prog)
            func.setName(new_name, SourceType.USER_DEFINED)
        except JAVA_ERRORS as e:
            fail(u"重命名失败: %s" % e)
        emit_result({
            "address": addr_str,
            "old_name": old_name,
            "new_name": new_name,
            "type": "function",
        })
    else:
        # 处理一般符号
        sym = prog.getSymbolTable().getPrimarySymbol(addr)
        if sym is None:
            fail(u"地址处无符号: %s" % addr_str)
        else:
            old_name = sym.getName()
            try:
                begin_mutation(prog)
                sym.setName(new_name, SourceType.USER_DEFINED)
            except JAVA_ERRORS as e:
                fail(u"重命名失败: %s" % e)
            emit_result({
                "address": addr_str,
                "old_name": old_name,
                "new_name": new_name,
                "type": str(sym.getSymbolType()),
            })
