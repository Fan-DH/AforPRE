# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""反编译指定函数为 C 伪代码。

参数：
  address: 函数入口地址（十六进制字符串，如 "0x401000"）
  name: 函数名（当 address 未提供时按名查找）
  timeout: 反编译超时秒（默认 60）
"""

from _common import parse_args, emit_result, fail, JAVA_ERRORS, resolve_function, warn

import re

from ghidra.app.decompiler import DecompInterface

params = parse_args(getScriptArgs())
prog = currentProgram
timeout = params.get("timeout", 60)

func = resolve_function(prog, params, toAddr)
decomp = DecompInterface()
stage = "open_program"
try:
    if not decomp.openProgram(prog):
        try:
            message = decomp.getLastMessage() or ""
        except JAVA_ERRORS as exc:
            message = u"无法取得 getLastMessage: %s" % exc
        fail(u"反编译器无法打开程序: %s" % (message or u"Ghidra 未提供底层原因"),
             code="ghidra.decompiler_open_failed",
             details={"stage": stage, "native_message": message},
             limitations=[u"没有获得 C 伪代码；反编译器初始化失败，不能推断目标函数没有逻辑。"],
             suggestions=[u"检查 Decompiler/os/<当前平台>/decompile 的可执行位、动态库及 noexec 挂载。",
                          u"结合 native_message 和完整 headless 日志定位原因；获准后修复对应文件，不要递归 chmod。"])
    stage = "decompile_function"
    res = decomp.decompileFunction(func, timeout, monitor)
    if not res.decompileCompleted():
        message = res.getErrorMessage() or u"Ghidra 未提供底层原因"
        timed_out = res.isTimedOut()
        fail(u"反编译失败: %s" % message, "timeout" if timed_out else "error",
             code="ghidra.decompile_timeout" if timed_out else "ghidra.decompile_failed",
             details={"stage": stage, "native_message": message, "timeout": timeout,
                      "cancelled": bool(res.isCancelled())},
             limitations=[u"函数反编译未完成，没有可作为完整逻辑使用的 C 输出。"],
             suggestions=[u"超时时检查函数大小和复杂控制流；其他失败请检查 native_message 与进程日志。"])
    decompiled = res.getDecompiledFunction()
    if decompiled is None or not decompiled.getC():
        fail(u"反编译完成标志为真，但没有可用的 C 输出", code="ghidra.decompile_empty",
             limitations=[u"Ghidra 未提供可用函数体；不能将缺失输出解释为函数为空或没有行为。"])
    code = decompiled.getC()
    # Ignore comments and string literals so user data cannot mimic an intrinsic.
    executable_text = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                             "", code, flags=re.DOTALL)
    bad_data = bool(re.search(r"\bhalt_baddata\s*\(", executable_text))
    slash = chr(92)
    double_quote = chr(34)
    quoted_literal = double_quote + "(?:" + slash + slash + ".|[^" + double_quote + slash + slash + "])*" + double_quote
    comment_text = re.sub(quoted_literal, "", code, flags=re.DOTALL)
    comments = re.findall(r"/\*.*?\*/|//[^\n]*", comment_text, re.DOTALL)
    warnings = [message for comment in comments for message in re.findall(r"WARNING:[^\n]*", comment)]
    # A software interrupt is valid machine code, but its handler/continuation
    # need not be represented in this function's C output.
    trap_intrinsics = sorted(set(re.findall(r"\b(swi|software_interrupt|trap)\s*\(", executable_text)))
    if trap_intrinsics:
        warn("ghidra.trap_control_flow", u"伪代码包含软件中断/陷阱 intrinsic。",
             u"异常处理器及恢复执行路径未验证；函数边界可能遗漏 trap 后的逻辑。合法 trap 不等于非法指令。",
             details={"intrinsics": trap_intrinsics, "cause_confirmed": False},
             suggestions=[u"用 ghidra_disassemble(mode=linear) 检查已知范围；结合 GDB 信号停止点验证真实执行路径。"])
    if bad_data:
        warn("ghidra.invalid_instruction", u"C 输出含 halt_baddata()：Ghidra 识别到非法指令或截断的控制流。",
             u"至少部分控制流未可靠恢复；不能把 halt_baddata 桩或空函数体当作无行为结论。"
             u"仅凭该输出无法确定原因，也不能确认运行时字节发生过变化。",
             details={"observed": "halt_baddata", "cause_confirmed": False,
                      "possible_causes": ["invalid_or_truncated_instruction", "incorrect_instruction_or_function_boundary",
                                          "wrong_language_or_image_base", "data_misidentified_as_code",
                                          "intentional_invalid_instruction", "static_runtime_bytes_mismatch"],
                      "causes_ranked": False},
             suggestions=[u"用 ghidra_read_bytes 和 ghidra_disassemble 核对入口字节与已识别指令。",
                          u"核对语言/指令集模式、基址、函数边界以及输入/patch 范围是否完整。",
                          u"若有动态执行证据，再比较对应地址的运行时字节与工程字节；根据差异选择后续操作。"])
    if warnings:
        warn("ghidra.decompile_warnings", u"反编译结果包含 Ghidra 警告。",
             u"当前伪代码存在反编译警告，部分控制流、调用约定或类型可能未可靠恢复。",
             details={"warnings": warnings},
             suggestions=[u"按具体 WARNING 核对指令重叠、函数边界、调用约定或类型；告警本身不确定根因。"])
    emit_result({
        "address": str(func.getEntryPoint()), "name": func.getName(), "decompiled": code,
        "quality": {"complete": False if (bad_data or warnings or trap_intrinsics) else None,
                    "completeness": "suspect" if (bad_data or warnings or trap_intrinsics) else "unknown",
                    "invalid_instruction": bad_data, "trap_intrinsics": trap_intrinsics,
                    "control_flow_verified": False,
                    "decompiler_completed": True, "warning_count": len(warnings),
                    "scope": "decompiler_output", "semantic_correctness_verified": False},
    })
except JAVA_ERRORS as exc:
    fail(u"反编译异常: %s" % exc, code="ghidra.decompiler_exception",
         details={"stage": stage, "exception": "%s" % exc},
         limitations=[u"反编译过程异常中止，没有可靠的完整函数逻辑。"])
finally:
    try:
        decomp.dispose()
    except JAVA_ERRORS as exc:
        warn("ghidra.decompiler_cleanup_failed", u"反编译器释放资源失败。",
             u"反编译器清理未完成；此前输出或失败原因保留，但进程资源释放状态未确认。",
             details={"exception": "%s" % exc})
