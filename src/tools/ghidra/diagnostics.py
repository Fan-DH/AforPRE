"""Structured diagnostics shared by the Ghidra process and Provider layers."""

from __future__ import annotations

import json
import re

from tools.base import ProviderError


def diagnostic(code, message, *, severity="warning", details=None, suggestions=None):
    return {"code": code, "severity": severity, "message": message,
            "details": details or {}, "suggestions": suggestions or []}


def unique(items):
    seen, result = set(), []
    for item in items:
        key = json.dumps(item, sort_keys=True, ensure_ascii=True)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def error(code, message, *, status="error", limitations=None, details=None,
          suggestions=None, data=None):
    return ProviderError(
        message, status, data=data,
        limitations=limitations or [f"Ghidra 操作未完成：{message}"],
        diagnostics=[diagnostic(code, message, severity="error", details=details,
                                suggestions=suggestions)],
    )


def classify_process(stdout, stderr, stage):
    """Classify observed log messages; do not guess a missing root cause."""
    observed = [line for line in (stdout + "\n" + stderr).splitlines()
                if not line.lstrip().startswith("{")]
    text = "\n".join(observed).lower()
    rules = [
        ("ghidra.java_runtime_failed", ["java runtime not found", "unsupportedclassversionerror", "unable to prompt user for jdk"],
         "Ghidra reported a Java bootstrap or version failure.",
         ["Check the service JAVA_HOME/PATH, JDK version and launch.properties; a stdio service cannot answer an interactive JDK prompt."]),
        ("ghidra.execution_permission_denied", ["permission denied", "error=13"],
         "Ghidra reported an execution or file permission failure.",
         ["Inspect the exact file path in the log, executable bits and noexec mount; repair only that file after permission is granted."]),
        ("ghidra.native_dependency_missing", ["error while loading shared libraries", "unsatisfiedlinkerror"],
         "A native library could not be loaded.",
         ["Check the named library, host platform and loader diagnostics; do not infer a package name without checking the log."]),
        ("ghidra.loader_failed", ["no importers", "no loadspec", "no load spec", "no supported loader"],
         "No supported loader configuration was found for the target.",
         ["Verify format, architecture and import options; raw binary language/base options are not exposed by this interface."]),
        ("ghidra.script_load_failed", ["importerror:", "no module named", "syntaxerror:", "noclassdeffounderror"],
         "A script or its runtime dependency failed to load.",
         ["Inspect the script/module path and Jython 2.7 compatibility in the complete log."]),
        ("ghidra.program_missing", ["no valid programs to process", "program not found"],
         "The cached program could not be found.",
         ["Verify project contents and target identity; back up before explicitly resetting the project."]),
    ]
    for code, needles, message, suggestions in rules:
        if any(needle in text for needle in needles):
            return diagnostic(code, message, severity="error",
                              details={"stage": stage, "observed_lines": observed[-10:]}, suggestions=suggestions)
    return None



def output_warnings(stdout, stderr, stage):
    """Preserve emitted warnings without asserting they are the root cause."""
    warning_pattern = re.compile(
        r"(?:^|\s)(?:WARN(?:ING)?|ERROR|SEVERE)(?:\s|:)|Exception in thread|"
        r"Traceback \(most recent call|[A-Za-z0-9_.]*(?:Exception|Error)\s*:|"
        r"permission denied|analysis timed out", re.IGNORECASE,
    )
    lines = [
        line.strip() for line in (stdout + "\n" + stderr).splitlines()
        if not line.lstrip().startswith("{") and warning_pattern.search(line)
    ]
    if not lines:
        return [], []
    partial = any("analysis" in line.lower() and ("timed out" in line.lower() or
                  "timeout" in line.lower()) for line in lines)
    message = "Ghidra 输出包含警告或错误日志；结构化结果不证明日志中的问题均已解决。"
    code = "ghidra.analysis_timeout" if partial else "ghidra.process_warnings"
    limitation = ("自动分析报告超时，后续查询基于未确认完整的分析状态。" if partial else message)
    return [diagnostic(code, message, details={"stage": stage, "lines": lines[-20:], "total_lines": len(lines), "lines_truncated": len(lines) > 20})], [limitation]
