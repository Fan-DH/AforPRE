"""契约层：跨引擎共享的输入输出约定。

统一契约：ToolResult / Record / Finding / 工具清单都是全局一份，
引擎差异通过 limitations / 可选字段下沉到引擎实现，上层不感知具体引擎。
"""

from .results import ToolResult, OK, ERROR, UNSUPPORTED_FORMAT, NOT_FOUND, TIMEOUT
from .record import Record
from .findings import Finding
from .tools import ToolContract, TOOL_CONTRACTS, get_tool_contract

__all__ = [
    "ToolResult", "OK", "ERROR", "UNSUPPORTED_FORMAT", "NOT_FOUND", "TIMEOUT",
    "Record", "Finding", "ToolContract", "TOOL_CONTRACTS", "get_tool_contract",
]