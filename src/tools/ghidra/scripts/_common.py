# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""postScript 公共辅助：参数解析与结构化结果输出。

所有 Ghidra postScript 通过 from _common import parse_args, emit_result 复用。
输出协议（与 runner.py 配合）：
    <<<APRE_RESULT_BEGIN>>>
    {json}
    <<<APRE_RESULT_END>>>
"""

import json
import os
import sys
import traceback

# Jython 默认编码是 ascii：源码里的非 ASCII 字面量（py2 的 byte str）与 unicode
# 混用时会被按 ascii/latin-1 隐式解码，产生 "å®ä¹..." 这类乱码。
# 这里把默认编码切到 utf-8，使 str→unicode 的隐式提升按 UTF-8 解码。
try:
    reload(sys)
    sys.setdefaultencoding("utf-8")
except Exception:
    pass

# Jython 中 Java 的 Throwable 并不是 Python Exception 的子类，
# `except Exception` 抓不到 Ghidra 抛出的 Java 异常（如 MemoryAccessException）。
# 脚本里统一用 JAVA_ERRORS 作为异常元组。
try:
    from java.lang import Throwable as _JavaThrowable
    JAVA_ERRORS = (Exception, _JavaThrowable)
except Exception:
    JAVA_ERRORS = (Exception,)


RESULT_BEGIN = "<<<APRE_RESULT_BEGIN>>>"
RESULT_END = "<<<APRE_RESULT_END>>>"
_mutation = None
_context = None

SCOPE_LIMITATIONS = {
    "inspect": [u"计数和概览基于当前静态定义，不能覆盖运行时生成、解密或自修改的内容。"],
    "decompile": [u"C 伪代码不是原始源码；类型、调用约定及间接控制流仍可能存在未恢复信息。"],
    "get_strings": [u"只返回 Ghidra 已定义的字符串；未识别、运行时解密或动态构造的字符串不在结果中。"],
    "list_functions": [u"函数列表依赖当前静态分析；未识别或运行时生成的函数不会自动补齐。"],
    "list_globals": [u"只列出当前符号表中符合类型过滤的符号，不能覆盖所有未定义全局数据。"],
    "get_cfg": [u"CFG 来自当前已识别指令；间接跳转和运行时修改的控制流可能不完整。"],
    "get_call_graph": [u"调用图来自当前静态分析；间接调用和运行时解析的目标可能缺失。"],
    "xrefs_from": [u"调用关系来自静态分析；无调用边不等于不存在动态或间接调用。"],
    "xrefs_to": [u"只返回当前引用管理器已识别的引用；无结果不证明地址没有运行时引用。"],
    "find_crypto": [u"特征常量匹配只提供候选线索，不证明算法存在；无匹配也不能排除加密。"],
    "disassemble": [u"只展示当前已识别指令和数据；未定义字节不会自动变成有效反汇编。"],
}
MUTATIONS = set(["rename_symbol", "set_signature", "patch_bytes", "add_comment", "define_string", "create_function"])


class _OperationFailure(BaseException):
    def __init__(self, message, status, diagnostic, limitations, data):
        self.message, self.status = message, status
        self.diagnostic, self.limitations, self.data = diagnostic, limitations, data


def diagnostic(code, message, severity="warning", details=None, suggestions=None):
    return {"code": code, "severity": severity, "message": message,
            "details": details or {}, "suggestions": suggestions or []}


def warn(code, message, limitation, details=None, suggestions=None):
    if _context is not None:
        _context["diagnostics"].append(diagnostic(code, message, details=details, suggestions=suggestions))
        _context["limitations"].append(limitation)


def _exception_info(exc):
    name = type(exc).__name__
    try:
        name = str(exc.getClass().getName())
    except Exception:
        pass
    causes, java_stack, inspection_error = [], [], None
    getter = getattr(exc, "getCause", None)
    if getter is not None:
        try:
            cause = getter()
            while cause is not None and len(causes) < 6:
                causes.append({"exception_type": str(cause.getClass().getName()), "message": "%s" % cause})
                following = cause.getCause()
                if following is cause:
                    break
                cause = following
            java_stack = [str(frame) for frame in exc.getStackTrace()][:20]
        except JAVA_ERRORS as cause_error:
            inspection_error = "%s" % cause_error
    text = ("%s" % exc) or (name + " (exception message unavailable)")
    lower = (name + " " + text + " " + " ".join(item["message"] for item in causes)).lower()
    code, status = "ghidra.script_exception", "error"
    suggestions = [u"检查诊断中的脚本、地址、异常类型及进程日志，不要重复调用猜测原因。"]
    if "cancel" in lower:
        code, status = "ghidra.cancelled", "error"
    elif "timeout" in lower or "timed out" in lower:
        code, status = "ghidra.timeout", "timeout"
    elif "permission" in lower or "accessdenied" in lower:
        code = "ghidra.permission_denied"
        suggestions = [u"检查诊断指向的文件权限；获准后只修复对应文件，不要递归修改整个安装目录。"]
    elif "memoryaccess" in lower or "memory access" in lower:
        code = "ghidra.memory_access_failed"
        suggestions = [u"用 ghidra_inspect 检查内存映射、初始化状态和基址，再核对地址及长度。"]
    elif "duplicatename" in lower or "duplicate name" in lower:
        code = "ghidra.duplicate_name"
        suggestions = [u"核对现有符号或参数名，选择不冲突的名称。"]
    elif "address" in lower and any(token in lower for token in ("overflow", "invalid", "outofbounds")):
        code = "ghidra.invalid_address_range"
        suggestions = [u"核对地址空间、加载基址及长度；地址加法不能超过当前地址空间。"]
    return diagnostic(code, text, "error", {"exception_type": name, "causes": causes, "java_stack": java_stack, "cause_inspection_error": inspection_error}, suggestions), status


def _rollback(result):
    try:
        had_mutation = _mutation is not None
        _end_mutation(False)
        if had_mutation:
            result["_diagnostics"].append(diagnostic(
                "ghidra.transaction_rolled_back", u"本次修改事务已回滚。", "info"))
            result["_limitations"].append(u"本次修改失败，事务已回滚；没有获得成功的修改结果。")
    except JAVA_ERRORS as exc:
        result["_diagnostics"].append(diagnostic(
            "ghidra.rollback_unconfirmed", u"回滚失败，项目状态无法确认。", "error",
            {"exception": "%s" % exc}))
        result["_limitations"].append(u"回滚未确认；可能残留部分修改，不应盲目重试，需检查项目状态。")


def dispatch(namespace, envelope=None, emit=True):
    """Guard every APRE postScript, including imports and transaction cleanup."""
    global _context
    parent_context = _context
    _context = {"operation": "dispatch", "params": {}, "result": None,
                "diagnostics": [], "limitations": []}
    result = None
    try:
        if envelope is None:
            raw = namespace["getScriptArgs"]()
            envelope = json.loads(raw[0]) if raw else {}
        if not isinstance(envelope, dict):
            fail("script envelope must be an object", code="ghidra.invalid_arguments")
        script, params = envelope.get("script"), envelope.get("arguments", {})
        if (not isinstance(script, basestring) or os.path.basename(script) != script
                or not script.endswith(".py") or script == "_dispatch.py"
                or (script.startswith("_") and script != "_noop.py")):
            fail(u"无效的脚本调度参数", code="ghidra.invalid_script")
        if not isinstance(params, dict):
            fail(u"脚本 arguments 必须是对象", code="ghidra.invalid_arguments")
        _context["operation"], _context["params"] = script[:-3], params
        if not (script == 'disassemble.py' and params.get('mode') == 'linear'):
            _context["limitations"].extend(SCOPE_LIMITATIONS.get(script[:-3], []))
        if script[:-3] in MUTATIONS:
            _context["limitations"].append(u"修改仅保存在 Ghidra 项目中，不修改或导出原始二进制文件。")
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script)
        if namespace.get("currentProgram") is None:
            fail(u"脚本没有可用的 currentProgram", code="ghidra.program_missing")
        scope = dict(namespace)
        scope["__file__"] = path
        scope["getScriptArgs"] = lambda: [json.dumps(params, ensure_ascii=True)]
        converter = scope.get("toAddr")
        if converter is not None and params.get("address"):
            original_converter = converter
            def checked_address(value):
                addr = original_converter(value)
                if addr is None:
                    fail(u"地址无法解析: %s" % value, code="ghidra.invalid_address",
                         suggestions=[u"核对地址空间、格式及加载基址。"])
                return addr
            scope["toAddr"] = checked_address
        with open(path, "rb") as source:
            # exec-mode code objects work with eval in both Python 2/Jython and Python 3.
            eval(compile(source.read(), path, "exec"), scope)
        result = _context["result"]
        if result is not None and not isinstance(result, dict):
            fail("script result must be an object", code="ghidra.invalid_script_result")
        if result is None:
            fail(u"脚本执行结束但未提供操作结果", code="ghidra.result_missing")
        # Validate serialization before committing a mutation.
        json.dumps(_ascii_safe(result), ensure_ascii=True)
        _end_mutation(True)
    except _OperationFailure as exc:
        result = {"_error": exc.message, "_status": exc.status, "_data": exc.data,
                  "_diagnostics": [exc.diagnostic], "_limitations": list(exc.limitations)}
        _rollback(result)
    except JAVA_ERRORS as exc:
        diag, status = _exception_info(exc)
        diag["details"]["traceback"] = traceback.format_exc()[-4000:]
        result = {"_error": diag["message"], "_status": status,
                  "_diagnostics": [diag],
                  "_limitations": [u"脚本异常中止，未获得完整可靠结果；不能将已收集的局部数据当作完整分析。"]}
        _rollback(result)
    except SystemExit as exc:
        result = {"_error": u"脚本提前退出: %s" % exc, "_status": "error",
                  "_diagnostics": [diagnostic("ghidra.script_exited", "%s" % exc, "error")],
                  "_limitations": [u"脚本提前退出，操作完成状态未确认。"]}
        _rollback(result)
    finally:
        if result is not None:
            result["_diagnostics"] = result.get("_diagnostics", []) + _context["diagnostics"]
            result["_limitations"] = result.get("_limitations", []) + _context["limitations"]
            for item in result["_diagnostics"]:
                item["details"].setdefault("operation", _context["operation"])
                for key in ("address", "name", "name_filter", "pattern", "length", "max_length", "types"):
                    if key in _context["params"]:
                        item["details"].setdefault(key, _context["params"][key])
            result["_limitations"] = list(dict.fromkeys(result["_limitations"]))
        _context = parent_context
    if emit:
        _write_result(result)
    return result


def parse_args(script_args):
    u"""从 getScriptArgs() 解析 JSON 参数，返回 dict。

    runner.py 把 Python 端的 args 编码成 JSON 字符串作为唯一参数传入。
    """
    if not script_args:
        return {}
    try:
        parsed = json.loads(script_args[0])
        if not isinstance(parsed, dict):
            raise ValueError("arguments must be an object")
        return parsed
    except Exception:
        fail(u"无法解析脚本参数")


def begin_mutation(prog):
    """Rollback the entire operation when a later step calls fail()."""
    global _mutation
    _mutation = (prog, prog.startTransaction("APRE mutation"))


def _end_mutation(commit):
    global _mutation
    if _mutation is not None:
        prog, transaction = _mutation
        prog.endTransaction(transaction, commit)
        _mutation = None


def resolve_function(prog, params, to_address):
    """Shared address/name lookup used by decompile, CFG and call queries."""
    fm = prog.getFunctionManager()
    addr_str, name = params.get("address"), params.get("name")
    try:
        if addr_str:
            addr = to_address(addr_str)
            func = fm.getFunctionAt(addr)
            if func is None:
                func = fm.getFunctionContaining(addr)
                if func is not None:
                    warn("ghidra.containing_function_selected", u"地址不是函数入口，使用包含该地址的函数。",
                         u"结果对应包含给定地址的函数，而不是该地址处独立存在的函数。")
        else:
            func = None
            found = []
            for sym in prog.getSymbolTable().getSymbols(name):
                candidate = fm.getFunctionAt(sym.getAddress())
                if candidate is not None and candidate not in found:
                    found.append(candidate)
            if len(found) > 1:
                fail(u"函数名存在多个候选: %s" % name, code="ghidra.ambiguous_function",
                     details={"candidates": [str(f.getEntryPoint()) for f in found]},
                     suggestions=[u"使用明确的函数入口 address 重试。"])
            func = found[0] if found else None
    except JAVA_ERRORS as exc:
        fail(u"函数地址或名称无效: %s" % exc)
    if func is None:
        fail(u"未找到函数: address=%s name=%s" % (addr_str, name), "not_found",
             code="ghidra.function_not_found",
             suggestions=[u"用 ghidra_list_functions 核对已识别函数；未识别代码不等于不存在逻辑。"])
    return func


def _ascii_safe(value):
    u"""递归把 bytes 解成 unicode，保证 json 输出可被 ascii 流打印。

    Jython 2.7 的 stdout 在 headless 下是 ascii 编码，直接 print 中文会
    UnicodeEncodeError；转成 unicode 后由 json.dumps(ensure_ascii=True)
    统一转义成 \\uXXXX，Python 侧 json.loads 再还原。
    """
    if isinstance(value, dict):
        return dict((_ascii_safe(k), _ascii_safe(v)) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return [_ascii_safe(v) for v in value]
    if isinstance(value, str):
        for enc in ("utf-8", "latin-1"):
            try:
                return value.decode(enc)
            except Exception:
                continue
        return value
    if isinstance(value, unicode):
        return value
    return value


def _write_result(result):
    u"""输出结构化结果（BEGIN/END 标记包裹 JSON）。"""
    text = json.dumps(_ascii_safe(result), ensure_ascii=True)
    if isinstance(text, unicode):
        text = text.encode("ascii", "backslashreplace")
    print(RESULT_BEGIN)
    print(text)
    print(RESULT_END)


def emit_result(result):
    if _context is None:
        _end_mutation(True)
        _write_result(result)
    else:
        if _context["result"] is not None:
            fail(u"脚本产生了多个结果", code="ghidra.multiple_results")
        _context["result"] = result


def fail(msg, status="error", code="ghidra.operation_failed", details=None,
         suggestions=None, limitations=None, data=None):
    u"""输出错误结果（仍走结构化通道，Python 端解析后由 ProviderError 处理）。"""
    # 不能对 unicode 消息调用 str()：py2 会用 ascii 编码而抛 UnicodeEncodeError
    limits = limitations or [u"操作未完成：%s；没有可作为完整结果使用的输出。" % msg]
    active = sys.exc_info()[1]
    if active is not None:
        observed, _ = _exception_info(active)
        details = dict(details or {})
        details.update(observed["details"])
        details["exception"] = "%s" % active
        if code == "ghidra.operation_failed":
            code = observed["code"]
        if suggestions is None:
            suggestions = observed["suggestions"]
    diag = diagnostic(code, msg, "error", details, suggestions)
    if _context is not None:
        raise _OperationFailure(msg, status, diag, limits, data)
    _end_mutation(False)
    _write_result({"_error": msg, "_status": status, "_limitations": limits,
                   "_diagnostics": [diag], "_data": data})
    raise SystemExit(0)
