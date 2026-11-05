# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""提取已定义字符串（带地址、长度、字符集）。

参数：
  pattern: 可选正则，过滤字符串内容（忽略大小写）
  min_length: 最小字符串长度，默认 4
"""

from _common import parse_args, emit_result, warn

import re as _re

params = parse_args(getScriptArgs())
prog = currentProgram
listing = prog.getListing()

pattern = params.get("pattern")
min_length = params.get("min_length", 4)

strings = []
unreadable = []
for d in listing.getDefinedData(True):
    if not d.hasStringValue():
        continue
    val = d.getValue()
    if val is None:
        unreadable.append(str(d.getAddress()))
        continue
    text = str(val)
    if len(text) < min_length:
        continue
    strings.append({
        "address": str(d.getAddress()),
        "text": text,
        "length": len(text),
        "charset": d.getDataType().getName(),
    })

if unreadable:
    warn("ghidra.string_values_skipped", "Some defined strings have no readable value.",
         "Strings at these addresses were skipped; this is not a complete list of defined string values.",
         details={"addresses": unreadable})

if pattern:
    rx = _re.compile(pattern, _re.IGNORECASE)
    matched = [s for s in strings if rx.search(s["text"])]
else:
    matched = strings

emit_result({
    "total": len(strings),
    "matched": matched,
    "count": len(matched),
})
