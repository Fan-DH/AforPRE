# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""读取程序的静态 image base 与格式信息（供动态调试的地址互译使用）。"""

from _common import parse_args, emit_result, fail, JAVA_ERRORS

params = parse_args(getScriptArgs())
prog = currentProgram

try:
    image_base = str(prog.getImageBase())
    language = str(prog.getLanguageID().getIdAsString())
    executable_format = str(prog.getExecutableFormat())
except JAVA_ERRORS as exc:
    fail(u"读取程序信息失败: %s" % exc, code="ghidra.debug.image_base_failed",
         suggestions=[u"用 ghidra_inspect 核对程序导入状态后重试。"])

emit_result({
    "image_base": image_base,
    "language": language,
    "executable_format": executable_format,
    "name": prog.getName(),
})
