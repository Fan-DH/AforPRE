# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""设置函数返回类型与参数名。

参数：
  address: 函数入口地址
  return_type: 返回类型字符串（如 "int", "char*", "void"）
  param_names: 参数名列表（如 ["argc", "argv"]）
"""

from _common import parse_args, emit_result, fail, JAVA_ERRORS, begin_mutation, warn

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    PointerDataType,
    VoidDataType, IntegerDataType, UnsignedIntegerDataType,
    CharDataType, UnsignedCharDataType,
    ShortDataType, UnsignedShortDataType,
    LongDataType, UnsignedLongDataType,
    LongLongDataType, UnsignedLongLongDataType,
    FloatDataType, DoubleDataType, ByteDataType,
)

params = parse_args(getScriptArgs())
prog = currentProgram
fm = prog.getFunctionManager()
dtm = prog.getDataTypeManager()

addr_str = params.get("address")
return_type = params.get("return_type")
param_names = params.get("param_names", [])

if not addr_str:
    fail(u"缺少参数: address")
else:
    addr = toAddr(addr_str)
    func = fm.getFunctionAt(addr)
    if func is None:
        func = fm.getFunctionContaining(addr)
    if func is None:
        fail(u"未找到函数: %s" % addr_str)
    else:
        changes = {}
        if not return_type and not param_names:
            fail(u"没有请求任何签名修改", code="ghidra.signature_no_changes",
                 limitations=[u"没有修改返回类型或参数名；address 单独使用不能产生签名修改。"],
                 suggestions=[u"提供 return_type 或非空 param_names。"])
        ps = func.getParameters()
        if len(param_names) > len(ps):
            fail(u"参数名数量超出函数参数数量")
        if len(set(param_names)) != len(param_names):
            fail(u"参数名不可重复")
        begin_mutation(prog)

        if return_type:
            # 内置类型不在 ProgramDTM 中，直接用构造函数创建
            TYPE_BUILDERS = {
                "void": lambda: VoidDataType(),
                "int": lambda: IntegerDataType(dtm),
                "uint": lambda: UnsignedIntegerDataType(dtm),
                "uint32": lambda: UnsignedIntegerDataType(dtm),
                "unsigned int": lambda: UnsignedIntegerDataType(dtm),
                "char": lambda: CharDataType(dtm),
                "uchar": lambda: UnsignedCharDataType(dtm),
                "unsigned char": lambda: UnsignedCharDataType(dtm),
                "byte": lambda: ByteDataType(dtm),
                "short": lambda: ShortDataType(dtm),
                "ushort": lambda: UnsignedShortDataType(dtm),
                "uint16": lambda: UnsignedShortDataType(dtm),
                "unsigned short": lambda: UnsignedShortDataType(dtm),
                "long": lambda: LongDataType(dtm),
                "ulong": lambda: UnsignedLongDataType(dtm),
                "unsigned long": lambda: UnsignedLongDataType(dtm),
                "long long": lambda: LongLongDataType(dtm),
                "unsigned long long": lambda: UnsignedLongLongDataType(dtm),
                "float": lambda: FloatDataType(dtm),
                "double": lambda: DoubleDataType(dtm),
            }

            def resolve_type(type_str):
                s = type_str.strip()
                if s.endswith("*"):
                    base = resolve_type(s[:-1].strip())
                    if base is None:
                        return None
                    return PointerDataType(base, dtm)
                builder = TYPE_BUILDERS.get(s)
                if builder is not None:
                    return builder()
                return None

            try:
                dt = resolve_type(return_type)
            except JAVA_ERRORS as e:
                fail(u"解析返回类型失败: %s" % e)
            if dt is None:
                fail(u"无法解析返回类型: %s" % return_type, code="ghidra.unsupported_return_type",
                     details={"supported_base_types": sorted(TYPE_BUILDERS.keys())},
                     limitations=[u"当前工具不是完整的 C 类型解析器，未应用不支持的返回类型。"])
            else:
                try:
                    func.setReturnType(dt, SourceType.USER_DEFINED)
                    changes["return_type"] = return_type
                except JAVA_ERRORS as e:
                    fail(u"设置返回类型失败: %s" % e)

        if param_names:
            applied = []
            for i, pname in enumerate(param_names):
                if i < len(ps):
                    try:
                        ps[i].setName(pname, SourceType.USER_DEFINED)
                        applied.append(pname)
                    except JAVA_ERRORS as e:
                        fail(u"设置参数名失败: %s" % e,
                             details={"parameter_index": i, "requested_name": pname})
            changes["param_names"] = applied
            if len(param_names) < len(ps):
                warn("ghidra.signature_partial_parameters", u"仅更新部分已有参数名。",
                     u"未重新构建参数类型或列表；未提供名称的已有参数保持原状态。",
                     details={"updated": len(param_names), "existing": len(ps)})

        emit_result({
            "address": addr_str,
            "function": func.getName(),
            "signature": func.getSignature().getPrototypeString(True),
            "changes": changes,
        })
