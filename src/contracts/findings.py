"""结论契约：区分观察 / 推导 / 推测 / 未知。

供后续组合工具 / 调查流程产出结论使用；当前 CLI / MCP 不消费它。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    statement: str
    kind: str  # observed | derived | inferred | unknown
    record_ids: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)