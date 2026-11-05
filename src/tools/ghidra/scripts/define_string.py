# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""在某地址定义字符串。

参数：
  address: 字符串起始地址
  string_type: 字符串类型（char/wchar/unicode），默认 char
"""

from _common import parse_args, emit_result, fail, JAVA_ERRORS, begin_mutation, warn

from ghidra.app.cmd.data import CreateDataCmd
from ghidra.program.model.data import (
    TerminatedStringDataType,
    TerminatedUnicodeDataType,
)

params = parse_args(getScriptArgs())
prog = currentProgram

addr_str = params.get("address")
string_type = params.get("string_type", "char")

if not addr_str:
    fail(u"缺少参数: address")
else:
    addr = toAddr(addr_str)
    listing = prog.getListing()

    if string_type not in ("char", "wchar", "unicode"):
        fail(u"无效字符串类型: %s" % string_type)
    if string_type in ("wchar", "unicode"):
        dt = TerminatedUnicodeDataType()
        if string_type == "wchar":
            warn("ghidra.wchar_encoding_assumed", u"wchar 请求使用 Ghidra 的终止 Unicode 字符串类型。",
                 u"当前实现未验证目标平台 wchar_t 的实际宽度或编码，不能保证与平台宽字符类型一致。")
    else:
        dt = TerminatedStringDataType()

    try:
        begin_mutation(prog)
        existing = listing.getDefinedDataAt(addr)
        if existing is not None:
            listing.clearCodeUnits(addr, addr.add(existing.getLength() - 1), False)
        cmd = CreateDataCmd(addr, dt)
        # Ghidra 11.x uses the single Program argument.
        success = cmd.applyTo(prog)
    except JAVA_ERRORS as e:
        fail(u"定义字符串异常: %s" % e)

    if not success:
        fail(u"定义字符串失败: %s" % cmd.getStatusMsg())
    else:
        data = listing.getDefinedDataAt(addr)
        if data is not None:
            val = data.getValue()
            if val is None:
                fail(u"定义后的字符串没有可读取的值", code="ghidra.defined_string_value_missing")
            emit_result({
                "address": addr_str,
                "value": str(val) if val else "",
                "length": data.getLength(),
                "type": data.getDataType().getName(),
            })
        else:
            fail(u"定义后未找到数据")
