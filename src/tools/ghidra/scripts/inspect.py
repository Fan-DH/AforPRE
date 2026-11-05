# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""程序概览：架构、入口、函数数、字符串数、内存块。"""

from _common import emit_result, warn

prog = currentProgram
fm = prog.getFunctionManager()
listing = prog.getListing()

# 统计函数数
func_count = 0
for f in fm.getFunctions(True):
    func_count += 1

# 统计已定义字符串数
string_count = 0
for d in listing.getDefinedData(True):
    if d.hasStringValue():
        string_count += 1

# 内存块
blocks = []
for block in prog.getMemory().getBlocks():
    blocks.append({
        "name": block.getName(),
        "start": str(block.getStart()),
        "end": str(block.getEnd()),
        "size": block.getSize(),
        "read": bool(block.isRead()),
        "write": bool(block.isWrite()),
        "execute": bool(block.isExecute()),
        "initialized": bool(block.isInitialized()),
    })

# 入口点
entry_points = []
for ep in prog.getSymbolTable().getExternalEntryPointIterator():
    entry_points.append(str(ep))

if len(entry_points) > 100:
    warn("ghidra.entry_points_truncated", u"入口点列表被截断为前 100 个。",
         u"程序存在 %s 个入口点，当前概览只展示前 100 个。" % len(entry_points),
         details={"total": len(entry_points), "returned": 100})
if func_count == 0:
    warn("ghidra.no_functions_identified", u"当前程序没有已识别函数。",
         u"无法从当前函数定义判断执行逻辑；未识别、加密代码或加载配置问题均需进一步检查。")

emit_result({
    "name": prog.getName(),
    "language": prog.getLanguage().getLanguageID().toString(),
    "compiler": prog.getCompilerSpec().getCompilerSpecID().toString(),
    "image_base": str(prog.getImageBase()),
    "entry_points": entry_points[:100],
    "entry_point_count": len(entry_points),
    "function_count": func_count,
    "string_count": string_count,
    "memory_blocks": blocks,
})
