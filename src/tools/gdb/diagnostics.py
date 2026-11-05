# -*- coding: utf-8 -*-
"""gdb 引擎的结构化诊断结构（与 ghidra.diagnostics 同级、引擎内自持）。"""

from __future__ import annotations

import json

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
        limitations=limitations or [f"gdb 操作未完成：{message}"],
        diagnostics=[diagnostic(code, message, severity="error", details=details,
                                suggestions=suggestions)],
    )
