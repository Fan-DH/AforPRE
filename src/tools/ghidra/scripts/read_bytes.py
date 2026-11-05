# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""读取某地址处的字节（hex + ascii dump）。

参数：
  address: 起始地址
  length: 读取字节数，默认 16
"""

from _common import parse_args, emit_result, fail, JAVA_ERRORS

from jarray import zeros

params = parse_args(getScriptArgs())
prog = currentProgram

addr_str = params.get("address")
length = params.get("length", 16)

if not addr_str:
    fail(u"缺少参数: address")
else:
    addr = toAddr(addr_str)
    buf = zeros(length, "b")
    try:
        count = prog.getMemory().getBytes(addr, buf)
        if count != length:
            fail(u"读取范围超出已初始化内存: 请求 %s 字节，实际 %s" % (length, count),
                 code="ghidra.short_memory_read",
                 limitations=[u"只获得 %s/%s 字节；不足部分没有用零填充，不能作为完整内存快照。" % (count, length)],
                 data={"address": addr_str, "requested_length": length, "read_length": count,
                       "bytes": [b & 0xff for b in buf[:count]]},
                 suggestions=[u"检查 ghidra_inspect 的内存块边界和初始化状态，或缩小 length。"])
    except JAVA_ERRORS as e:
        fail(u"读取失败: %s" % e)
    else:
        bytes_list = [b & 0xff for b in buf]
        hex_str = " ".join("%02x" % b for b in bytes_list)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in bytes_list)
        emit_result({
            "address": addr_str,
            "length": length,
            "bytes": bytes_list,
            "hex": hex_str,
            "ascii": ascii_str,
        })
