# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""获取函数的控制流图（基本块 + 前驱/后继边）。

参数：
  address: 函数入口地址
  name: 函数名（当 address 未提供时按名查找）
"""

from _common import parse_args, emit_result, fail, resolve_function, warn

from ghidra.program.model.block import BasicBlockModel

params = parse_args(getScriptArgs())
prog = currentProgram
fm = prog.getFunctionManager()

addr_str = params.get("address")
name = params.get("name")

func = resolve_function(prog, params, toAddr)

if func is None:
    fail(u"未找到函数: address=%s name=%s" % (addr_str, name))
else:
    body = func.getBody()
    model = BasicBlockModel(prog)
    block_list = []

    for block in model.getCodeBlocksContaining(body, monitor):
        if not body.contains(block.getFirstStartAddress()):
            continue
        preds = []
        src_it = block.getSources(monitor)
        while src_it.hasNext():
            ref = src_it.next()
            source = ref.getSourceBlock()
            preds.append(str(source.getFirstStartAddress() if source else ref.getSourceAddress()))
        succs = []
        dst_it = block.getDestinations(monitor)
        while dst_it.hasNext():
            ref = dst_it.next()
            destination = ref.getDestinationBlock()
            succs.append(str(destination.getFirstStartAddress() if destination else ref.getDestinationAddress()))
        block_list.append({
            "start": str(block.getFirstStartAddress()),
            "end": str(block.getMaxAddress()),
            "size": block.getNumAddresses(),
            "predecessors": preds,
            "successors": succs,
        })

    if not block_list:
        warn("ghidra.cfg_empty", u"函数存在，但没有生成已识别的基本块。",
             u"没有获得可用 CFG；可能缺少有效指令或函数边界定义，不能据此认为函数没有控制流。",
             suggestions=[u"检查函数入口的 ghidra_read_bytes 和 ghidra_disassemble 结果以及加载配置。"])
    emit_result({
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "blocks": block_list,
        "block_count": len(block_list),
    })
