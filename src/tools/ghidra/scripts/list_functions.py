# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""列出所有函数（地址、名、大小、签名、是否 thunk）。"""

from _common import parse_args, emit_result

import re as _re

params = parse_args(getScriptArgs())
prog = currentProgram
fm = prog.getFunctionManager()

name_filter = params.get("name_filter")
include_thunk = params.get("include_thunk", True)
rx = _re.compile(name_filter, _re.IGNORECASE) if name_filter else None

functions = []
for f in fm.getFunctions(True):
    if not include_thunk and f.isThunk():
        continue
    entry = str(f.getEntryPoint())
    name = f.getName()
    if rx is not None:
        if not rx.search(name):
            continue
    functions.append({
        "address": entry,
        "name": name,
        "size": f.getBody().getNumAddresses(),
        "is_thunk": bool(f.isThunk()),
        "calling_convention": f.getCallingConventionName(),
        "signature": f.getSignature().getPrototypeString(True),
    })

emit_result({
    "functions": functions,
    "count": len(functions),
})
