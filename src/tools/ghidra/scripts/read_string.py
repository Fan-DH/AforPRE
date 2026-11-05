# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""读取某地址处的字符串（优先读已定义数据，否则按 C 字符串读取）。

参数：
  address: 字符串起始地址
  max_length: 按 C 字符串读取时的最大长度，默认 256
"""

from _common import parse_args, emit_result, fail, JAVA_ERRORS, warn

from jarray import zeros

params = parse_args(getScriptArgs())
prog = currentProgram

addr_str = params.get("address")
max_length = params.get("max_length", 256)

if not addr_str:
    fail(u"缺少参数: address")
else:
    addr = toAddr(addr_str)
    listing = prog.getListing()

    # 1. 优先从已定义数据读取
    data = listing.getDefinedDataAt(addr)
    if data is not None and data.hasStringValue():
        val = data.getValue()
        if val is None:
            fail(u"已定义字符串没有可读取的值", code="ghidra.string_value_missing")
        emit_result({
            "address": addr_str,
            "value": str(val) if val else "",
            "length": data.getLength(),
            "type": data.getDataType().getName(),
            "defined": True,
        })
    else:
        # 2. 按 C 字符串手动读取到 null
        buf = zeros(max_length, "b")
        try:
            count = prog.getMemory().getBytes(addr, buf)
            if count <= 0:
                fail(u"没有读到字符串字节", code="ghidra.memory_read_empty")
        except JAVA_ERRORS as e:
            fail(u"读取失败: %s" % e)
        else:
            chars = []
            terminated = False
            for b in buf[:count]:
                if b == 0:
                    terminated = True
                    break
                chars.append(chr(b & 0xff))
            warn("ghidra.raw_string_fallback", u"地址没有已定义字符串，使用原始 C 字符串读取。",
                 u"字符串编码未由数据类型确认；原始字节展示不能保证字符集判断正确。",
                 details={"read_length": count})
            if not terminated:
                warn("ghidra.string_truncated", u"读取范围内没有发现字符串终止符。",
                     u"只返回当前可读范围或 max_length 内的片段，不能当成完整字符串。",
                     details={"read_length": count, "max_length": max_length},
                     suggestions=[u"检查内存块边界和编码；必要时扩大 max_length 或定义正确的字符串类型。"])
            emit_result({
                "address": addr_str,
                "value": "".join(chars),
                "length": len(chars),
                "type": "raw_cstring",
                "defined": False,
                "terminated": terminated,
                "truncated": not terminated,
                "bytes": [b & 0xff for b in buf[:len(chars)]],
            })
