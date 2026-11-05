# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""添加注释。

参数：
  address: 注释地址
  comment: 注释内容
  comment_type: 注释类型（plate/pre/post/eol），默认 eol
"""

from _common import parse_args, emit_result, fail, JAVA_ERRORS, begin_mutation, warn

from ghidra.program.model.listing import CodeUnit

params = parse_args(getScriptArgs())
prog = currentProgram

addr_str = params.get("address")
comment = params.get("comment")
comment_type = params.get("comment_type", "eol")

type_map = {
    "plate": CodeUnit.PLATE_COMMENT,
    "pre": CodeUnit.PRE_COMMENT,
    "post": CodeUnit.POST_COMMENT,
    "eol": CodeUnit.EOL_COMMENT,
}

if not addr_str or comment is None:
    fail(u"缺少参数: address 和 comment")
else:
    addr = toAddr(addr_str)
    listing = prog.getListing()
    cu = listing.getCodeUnitAt(addr)
    if cu is None:
        # 尝试获取包含该地址的 CodeUnit
        cu = listing.getCodeUnitContaining(addr)
    if cu is None:
        fail(u"地址处无代码单元: %s" % addr_str)
    else:
        if comment_type not in type_map:
            fail(u"无效注释类型: %s" % comment_type)
        ct = type_map[comment_type]
        try:
            begin_mutation(prog)
            cu.setComment(ct, comment)
        except JAVA_ERRORS as e:
            fail(u"添加注释失败: %s" % e)
        actual = str(cu.getMinAddress())
        if actual != str(addr):
            warn("ghidra.comment_containing_unit", u"注释应用到包含该地址的代码单元。",
                 u"注释不是附着在单元内部的独立字节上；实际代码单元地址已在 actual_address 中返回。",
                 details={"actual_address": actual})
        emit_result({
            "address": addr_str,
            "comment": comment,
            "comment_type": comment_type,
            "actual_address": actual,
        })
