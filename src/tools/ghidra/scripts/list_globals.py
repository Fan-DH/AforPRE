# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""列出全局符号（非函数的标签/数据符号）。"""

from _common import parse_args, emit_result, warn

import re as _re

from ghidra.program.model.symbol import SymbolType

params = parse_args(getScriptArgs())
prog = currentProgram
st = prog.getSymbolTable()

name_filter = params.get("name_filter")
# 只取 LABEL 和 NAMESPACE 类型（排除 FUNCTION，函数用 list_functions）
# SymbolType.toString() 返回 "Label"/"Function" 这类首字母大写形式，
# 故统一大写后再比对，避免调用方传 "LABEL" 时永远筛不到。
types = params.get("types", ["LABEL"])
wanted = set(t.upper() for t in types)
rx = _re.compile(name_filter, _re.IGNORECASE) if name_filter else None

symbols = []
unaddressed = []
for sym in st.getAllSymbols(True):
    stype = sym.getSymbolType().toString()
    if stype.upper() not in wanted:
        continue
    name = sym.getName()
    if rx is not None:
        if not rx.search(name):
            continue
    addr = sym.getAddress()
    if addr is None:
        unaddressed.append(name)
        continue
    symbols.append({
        "address": str(addr),
        "name": name,
        "type": stype,
        "global": bool(sym.isGlobal()),
    })

if unaddressed:
    warn("ghidra.symbol_addresses_skipped", "Some symbols have no usable address.",
         "Symbols without addresses were excluded from the result.", details={"symbols": unaddressed})

emit_result({
    "symbols": symbols,
    "count": len(symbols),
})
