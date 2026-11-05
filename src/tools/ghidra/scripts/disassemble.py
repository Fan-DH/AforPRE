# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""反汇编指定地址范围。

参数：
  address: 起始地址
  length: 反汇编字节数，默认 64
"""

from _common import parse_args, emit_result, fail, JAVA_ERRORS, warn

def linear_disassemble(prog, addr, length):
    from ghidra.app.util import PseudoDisassembler
    decoder = PseudoDisassembler(prog)
    items, decoded, reason, error_message = [], 0, 'end', None
    while decoded < length:
        monitor.checkCancelled()
        cur = addr.add(decoded)
        try:
            inst = decoder.disassemble(cur)
            if inst is None or inst.getLength() <= 0:
                raise ValueError('decoder returned no instruction')
            size = inst.getLength()
            if size > length - decoded:
                reason = 'instruction_crosses_end'
                break
            raw = inst.getBytes()
            items.append({'address': str(cur), 'type': 'instruction',
                          'mnemonic': inst.getMnemonicString(),
                          'operands': [inst.getDefaultOperandRepresentation(i) for i in range(inst.getNumOperands())],
                          'bytes': ' '.join('%02x' % (b & 0xff) for b in raw), 'length': size})
            decoded += size
        except JAVA_ERRORS as exc:
            reason, error_message = 'decode_failed', str(exc)
            break
    if decoded != length:
        warn('ghidra.linear_decode_incomplete', u'给定范围未完整解码。',
             u'在失败或越界指令处停止，未跳过字节或猜测下一条指令边界。',
             details={'address': str(addr.add(decoded)), 'reason': reason, 'error': error_message})
    emit_result({'start': str(addr), 'end_exclusive': str(addr.add(length)), 'length': length,
                 'mode': 'linear', 'items': items, 'decoded_length': decoded,
                 'complete': decoded == length, 'termination': reason,
                 'next_address': str(addr.add(decoded)), 'program_modified': False,
                 'control_flow_verified': False,
                 '_limitations': [u'线性解码采用工程语言和地址上下文；数据也可能解码成合法指令。结果不证明函数边界或真实执行路径。']})


params = parse_args(getScriptArgs())
prog = currentProgram

addr_str = params.get("address")
length = params.get("length", 64)

if not addr_str:
    fail(u"缺少参数: address")
elif params.get("mode", "listing") == "linear":
    linear_disassemble(prog, toAddr(addr_str), length)
else:
    addr = toAddr(addr_str)
    end_addr = addr.add(length)
    listing = prog.getListing()
    fm = prog.getFunctionManager()

    items = []
    cur = addr
    while cur.compareTo(end_addr) < 0:
        inst = listing.getInstructionAt(cur)
        if inst is not None:
            if inst.getLength() <= 0:
                fail("instruction has a non-positive length", code="ghidra.invalid_code_unit_length")
            operands = []
            for i in range(inst.getNumOperands()):
                operands.append(inst.getDefaultOperandRepresentation(i))
            try:
                raw_bytes = inst.getBytes()
                if raw_bytes is not None:
                    hex_bytes = " ".join("%02x" % (b & 0xff) for b in raw_bytes)
                else:
                    hex_bytes = ""
                    warn("ghidra.instruction_bytes_missing", u"指令对象没有可读取的原始字节。",
                         u"部分指令只提供文本表示，不能据此验证原始机器码。",
                         details={"instruction_address": str(cur)})
            except JAVA_ERRORS as exc:
                hex_bytes = ""
                warn("ghidra.instruction_bytes_unreadable", u"读取指令原始字节失败。",
                     u"部分指令的机器码没有读取成功，空 bytes 字段不代表指令没有字节。",
                     details={"instruction_address": str(cur), "exception": "%s" % exc})
            func = fm.getFunctionContaining(cur)
            items.append({
                "address": str(cur),
                "type": "instruction",
                "mnemonic": inst.getMnemonicString(),
                "operands": operands,
                "bytes": hex_bytes,
                "length": inst.getLength(),
                "function": func.getName() if func else "",
            })
            cur = cur.add(inst.getLength())
        else:
            d = listing.getDefinedDataAt(cur)
            if d is not None:
                if d.getLength() <= 0:
                    fail("data unit has a non-positive length", code="ghidra.invalid_code_unit_length")
                val = d.getValue()
                items.append({
                    "address": str(cur),
                    "type": "data",
                    "data_type": d.getDataType().getName(),
                    "value": str(val) if val is not None else "",
                    "length": d.getLength(),
                })
                cur = cur.add(d.getLength())
            else:
                # 未定义字节
                try:
                    b = prog.getMemory().getByte(cur) & 0xff
                except JAVA_ERRORS as exc:
                    fail(u"读取未定义字节失败: %s" % exc,
                         data={"start": addr_str, "requested_length": length, "items": items},
                         limitations=[u"反汇编范围没有完整读取；已收集的 items 只是失败前的片段。"])
                items.append({
                    "address": str(cur),
                    "type": "byte",
                    "value": "%02x" % b,
                    "length": 1,
                })
                cur = cur.add(1)

    emit_result({
        "start": addr_str,
        "length": length,
        "items": items,
    })
