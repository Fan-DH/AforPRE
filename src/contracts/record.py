"""记录数据结构（操作级）。

一条 Record 对应一次引擎分析操作，记录目标、操作、参数与结果。
数据结构属于 IO 契约，与具体存储实现分离（存储见 records/）。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Record:
    id: str
    target: str
    operation: str
    parameters: dict
    result: Any
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)