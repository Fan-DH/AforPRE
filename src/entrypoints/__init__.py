"""入口层：CLI 与 MCP 共用工具调度，各自作为对外入口。"""

from .dispatcher import ToolDispatcher

__all__ = ["ToolDispatcher"]