# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""Define a caller-declared, exactly bounded linear function in a transaction."""
from _common import parse_args, emit_result, fail, begin_mutation, warn
from ghidra.app.util import PseudoDisassembler
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType

params = parse_args(getScriptArgs())
prog = currentProgram
start = toAddr(params['address'])
length = params['length']
end = start.add(length - 1)
body = AddressSet(start, end)
listing, manager = prog.getListing(), prog.getFunctionManager()
name = params.get('name') or ('FUN_' + str(start))
functions = list(manager.getFunctionsOverlapping(body))
# Do not clear a data/instruction unit extending outside the caller's range.
for edge in (start, end):
    unit = listing.getCodeUnitContaining(edge)
    if unit is not None and (unit.getMinAddress().compareTo(start) < 0 or unit.getMaxAddress().compareTo(end) > 0):
        fail(u'范围截断现有代码/数据单元，拒绝扩大修改范围。', code='ghidra.function_boundary_conflict',
             details={'unit_start': str(unit.getMinAddress()), 'unit_end': str(unit.getMaxAddress())})
for function in functions:
    if not body.contains(function.getBody()):
        fail(u'已有函数跨越指定范围，拒绝修改其范围外部分。', code='ghidra.function_overlap',
             details={'function': function.getName(), 'entry': str(function.getEntryPoint())})
identical = (len(functions) == 1 and functions[0].getEntryPoint() == start and
             functions[0].getBody().equals(body) and functions[0].getName() == name)
if functions and not identical and not params.get('replace_existing', False):
    fail(u'范围内已有函数；确认边界后可显式 replace_existing=true。', code='ghidra.function_overlap',
         details={'functions': [{'name': f.getName(), 'entry': str(f.getEntryPoint())} for f in functions]})
# Preflight all instructions, including bytes after trap/ret/jmp. No writes yet.
decoder, starts, offset = PseudoDisassembler(prog), [], 0
while offset < length:
    monitor.checkCancelled()
    address = start.add(offset)
    inst = decoder.disassemble(address)
    if inst is None or inst.getLength() <= 0 or offset + inst.getLength() > length:
        fail(u'范围未恰好覆盖完整可解码指令，未创建函数。', code='ghidra.function_decode_incomplete',
             details={'address': str(address), 'decoded_length': offset})
    starts.append((address, inst.getLength()))
    offset += inst.getLength()
# An identical function declaration can still contain data or undefined bytes.
# Do not call that a successful no-op without checking the listing too.
if identical:
    for address, size in starts:
        existing = listing.getInstructionAt(address)
        if existing is None or existing.getLength() != size:
            identical = False
            break
    if not identical and not params.get('replace_existing', False):
        fail(u'已有函数范围相同但代码定义不完整；需显式 replace_existing=true 重建。',
             code='ghidra.function_definition_incomplete')
replaced = []
if not identical:
    begin_mutation(prog)
    for function in functions:
        replaced.append({'name': function.getName(), 'entry': str(function.getEntryPoint())})
        manager.removeFunction(function.getEntryPoint())
    listing.clearCodeUnits(start, end, False)
    # Seed every linear instruction boundary; do not follow branches outside body.
    for address, size in starts:
        monitor.checkCancelled()
        existing = listing.getInstructionAt(address)
        if existing is None:
            command = DisassembleCommand(address, body, False)
            if not command.applyTo(prog, monitor):
                fail(u'代码定义失败，回滚本次修改。', code='ghidra.function_define_failed',
                     details={'address': str(address), 'message': command.getStatusMsg()})
        existing = listing.getInstructionAt(address)
        if existing is None or existing.getLength() != size:
            fail(u'实际指令边界与预览不符，回滚本次修改。', code='ghidra.function_define_failed')
    function = manager.createFunction(name, start, body, SourceType.USER_DEFINED)
    if function is None or not function.getBody().equals(body):
        fail(u'函数范围未按请求建立，回滚本次修改。', code='ghidra.function_create_failed')
warn('ghidra.user_defined_function', u'函数范围由调用者指定，控制流未验证。',
     u'线性可解码不证明所有字节均会执行；异常处理、间接跳转及反编译完整性仍需验证。')
emit_result({'address': str(start), 'end_exclusive': str(end.add(1)), 'length': length,
             'name': name, 'instruction_count': len(starts), 'replaced_functions': replaced,
             'program_modified': not identical, 'control_flow_verified': False,
             'body_source': 'user_declared_linear_range'})
