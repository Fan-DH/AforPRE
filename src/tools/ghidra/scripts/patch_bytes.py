# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""修改字节（patch）。

参数：
  address: 起始地址
  bytes: 要写入的字节列表（如 [0x90, 0x90, 0xc3]）
"""

from _common import parse_args, emit_result, fail, JAVA_ERRORS, begin_mutation, warn

from jarray import zeros
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.util import PseudoDisassembler

params = parse_args(getScriptArgs())
prog = currentProgram

addr_str = params.get("address")
patch_bytes_list = params.get("bytes")

if not addr_str or not patch_bytes_list:
    fail(u"缺少参数: address 和 bytes")
else:
    addr = toAddr(addr_str)
    length = len(patch_bytes_list)
    rebuild = bool(params.get("rebuild_code", False))
    reanalyze = bool(params.get("reanalyze", False))
    analysis_complete = False
    auto_analysis_complete = False
    redisassembled = None
    function_rebuild_complete = None
    function_results = []
    boundary_crossings = []
    if any(not isinstance(b, (int, long)) or isinstance(b, bool) or
           b < 0 or b > 255 for b in patch_bytes_list):
        fail(u"bytes 必须是 0-255 的整数列表")

    # 备份原字节
    orig = zeros(length, "b")
    ok = True
    try:
        count = prog.getMemory().getBytes(addr, orig)
        if count != length:
            fail(u"读取原字节不完整，拒绝 patch")
    except JAVA_ERRORS as e:
        fail(u"读取原字节失败: %s" % e)
        ok = False
    orig_list = [b & 0xff for b in orig]
    if params.get("original_path"):
        # Archive rollback bytes before changing the project, not after saving it.
        with open(params["original_path"], "wb") as backup:
            backup.write("".join(chr(b) for b in orig_list))

    # 写入新字节
    # Jython 的 jarray 'b' 是 signed byte，>0x7f 需转成负值，否则 OverflowError
    new_buf = zeros(length, "b")
    for i, b in enumerate(patch_bytes_list):
        v = int(b) & 0xff
        new_buf[i] = v - 256 if v > 0x7f else v

    if ok:
        try:
            begin_mutation(prog)
            listing = prog.getListing()
            # Data bytes may be patched without erasing their types. Only clear
            # overlapping instructions, and only those regions are redisassembled.
            code_starts = []
            end = addr.add(length - 1)
            current = addr
            while current.compareTo(end) <= 0:
                instruction = listing.getInstructionContaining(current)
                if instruction is not None:
                    code_starts.append(instruction.getMinAddress())
                    current = instruction.getMaxAddress().add(1)
                else:
                    current = current.add(1)
            affected_functions = list(prog.getFunctionManager().getFunctionsOverlapping(AddressSet(addr, end)))
            if code_starts or rebuild:
                listing.clearCodeUnits(addr, end, False)
            prog.getMemory().setBytes(addr, new_buf)
            verified = zeros(length, "b")
            count = prog.getMemory().getBytes(addr, verified)
            if count != length or [b & 0xff for b in verified] != list(patch_bytes_list):
                fail(u"写入后字节验证失败", code="ghidra.patch_verification_failed",
                     limitations=[u"未确认 patch 字节与请求一致，拒绝提交该修改事务。"])
        except JAVA_ERRORS as e:
            fail(u"写入失败: %s" % e)
            ok = False
        else:
            # Start at the supplied instruction boundary, not obsolete boundaries.
            try:
                starts = [addr] if rebuild else code_starts
                if starts:
                    if rebuild:
                        command = DisassembleCommand(addr, AddressSet(addr, end), True)
                        redisassembled = (bool(command.applyTo(prog, monitor)) and
                                          listing.getInstructionAt(addr) is not None)
                    else:
                        redisassembled = all([bool(disassemble(start)) for start in starts])
                    if not redisassembled:
                        warn("ghidra.patch_redisassembly_failed", u"字节已修改，但范围内重新反汇编未完成。",
                             u"需要检查真实指令边界、入口和代码范围。")
            except JAVA_ERRORS as exc:
                redisassembled = False
                warn("ghidra.patch_analysis_incomplete", u"字节已修改，但代码重建/分析未完成。",
                     u"请检查代码定义；不能把当前伪代码视为完整恢复结果。",
                     details={"exception": "%s" % exc})

            if rebuild:
                function_rebuild_complete = bool(redisassembled)
                if redisassembled:
                    for function in affected_functions:
                        entry = function.getEntryPoint()
                        item = {"address": str(entry), "name": function.getName()}
                        try:
                            if listing.getInstructionAt(entry) is None:
                                raise RuntimeError("function entry has no decoded instruction")
                            changed = CreateFunctionCmd.fixupFunctionBody(prog, function, monitor)
                            # Ghidra 11.2.1 returns false for an already-correct body too.
                            expected = CreateFunctionCmd.getFunctionBody(prog, entry, False, monitor)
                            valid = (expected is not None and not expected.isEmpty() and
                                     function.getBody().equals(expected))
                            if not changed and not valid:
                                raise RuntimeError("function body could not be reconciled")
                            item["status"] = "updated" if changed else "unchanged"
                        except JAVA_ERRORS as exc:
                            function_rebuild_complete = False
                            item.update({"status": "failed", "error": "%s" % exc})
                            warn("ghidra.patch_function_rebuild_failed", u"受影响函数体未能重建。",
                                 u"该函数边界可能过期；其他函数与增量分析仍会继续处理。", details=item)
                        function_results.append(item)
                    if prog.getFunctionManager().getFunctionContaining(addr) is None:
                        try:
                            if createFunction(addr, None) is None:
                                raise RuntimeError("function creation failed")
                        except JAVA_ERRORS as exc:
                            function_rebuild_complete = False
                            warn("ghidra.patch_function_rebuild_failed", u"无法在同步起点建立函数。",
                                 u"请核对起点是否为函数入口。", details={"exception": "%s" % exc})

            # A body fixup failure must not suppress all reference/type analysis.
            if reanalyze:
                try:
                    analyzeChanges(prog)
                    auto_analysis_complete = not monitor.isCancelled()
                except JAVA_ERRORS as exc:
                    warn("ghidra.patch_analysis_incomplete", u"增量自动分析未完成。",
                         u"字节已保存，但分析信息可能过期。", details={"exception": "%s" % exc})
                analysis_complete = (auto_analysis_complete and redisassembled is not False and
                                     function_rebuild_complete is not False)

            if rebuild:
                # Restricted disassembly may refuse an instruction cut by the end.
                # Preview only known starts, without defining code or extending writes.
                candidates = [addr]
                previous = listing.getInstructionBefore(end.add(1))
                if previous is not None and previous.getMinAddress().compareTo(addr) >= 0:
                    fallthrough = previous.getFallThrough()
                    if fallthrough is not None and fallthrough.compareTo(end) <= 0:
                        candidates.append(fallthrough)
                for candidate in candidates:
                    if listing.getInstructionAt(candidate) is None:
                        try:
                            preview = PseudoDisassembler(prog).disassemble(candidate)
                            if preview is not None and preview.getMaxAddress().compareTo(end) > 0:
                                crossing = {"start": str(preview.getMinAddress()),
                                            "end": str(preview.getMaxAddress()), "source": "decode_preview"}
                                if crossing not in boundary_crossings:
                                    boundary_crossings.append(crossing)
                        except JAVA_ERRORS as exc:
                            warn("ghidra.patch_range_check_incomplete", u"无法预览同步边界处的指令。",
                                 u"未确认范围是否覆盖完整指令。", details={"exception": "%s" % exc})
                for edge in (addr, end):
                    instruction = listing.getInstructionContaining(edge)
                    if instruction is not None and (instruction.getMinAddress().compareTo(addr) < 0 or
                                                    instruction.getMaxAddress().compareTo(end) > 0):
                        crossing = {"start": str(instruction.getMinAddress()),
                                    "end": str(instruction.getMaxAddress()), "source": "listing"}
                        if crossing not in boundary_crossings:
                            boundary_crossings.append(crossing)
                if boundary_crossings:
                    warn("ghidra.patch_range_boundary", u"同步范围边界落在已识别或预览解码的指令内部。",
                         u"完整解码这些指令需要范围外工程字节；自动分析完成不代表快照完整。",
                         details={"instructions": boundary_crossings},
                         suggestions=[u"核对真实指令边界和完整代码范围，确认缺失字节后再同步；工具不会自动扩大写入范围。"])

    if ok:
        output = {
            "address": addr_str,
            "length": length,
            "redisassembly_complete": redisassembled,
            "code_modified": bool(code_starts) or rebuild,
            "analysis_complete": analysis_complete,
            "analysis_requested": reanalyze,
            "analysis_status": ("completed" if analysis_complete else "incomplete") if reanalyze else "not_requested",
            "auto_analysis_complete": auto_analysis_complete,
            "analysis_scope": "incremental_patch_analysis",
            "function_rebuild_complete": function_rebuild_complete,
            "function_rebuild_results": function_results,
            "range_boundary_crossings": boundary_crossings,
        }
        if params.get("include_bytes", True):
            output.update({"original": orig_list, "patched": list(patch_bytes_list)})
        emit_result(output)
        if (code_starts or rebuild) and not analysis_complete:
            warn("ghidra.patch_analysis_stale", u"patch 后重建/增量分析未全部完成或未请求分析。",
                 u"函数、交叉引用、类型及控制流信息可能过期；请结合各阶段状态判断。",
                 details={"analysis_requested": reanalyze, "auto_analysis_complete": auto_analysis_complete,
                          "function_rebuild_complete": function_rebuild_complete})
