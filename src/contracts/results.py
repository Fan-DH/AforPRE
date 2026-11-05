"""工具调用的结果约定。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# 结果状态
OK = "ok"
ERROR = "error"
UNSUPPORTED_FORMAT = "unsupported_format"
NOT_FOUND = "not_found"
TIMEOUT = "timeout"


@dataclass
class ToolResult:
    """一次工具调用的结果，明确区分成功与失败原因。"""

    status: str = OK
    data: Any = None
    error: str | None = None
    limitations: list[str] = field(default_factory=list)
    record_id: str | None = None
    diagnostics: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
