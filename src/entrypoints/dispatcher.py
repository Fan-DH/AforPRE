"""工具调度：按工具名执行操作并记录，CLI 与 MCP 共享。

工具清单来自 contracts.tools；执行委托给注入的引擎 provider；
每次操作产生一条操作级 Record 写入 records。
"""

from __future__ import annotations

import os
import time

from contracts.record import Record
from contracts.results import ERROR, OK, ToolResult
from contracts.tools import TOOL_CONTRACTS, get_tool_contract
from records.store import RecordStore
from tools.base import ProviderError


class ToolDispatcher:
    def __init__(self, provider, store: RecordStore):
        self.provider = provider
        self.store = store

    def list_tools(self) -> list[dict]:
        return [
            {"name": c.name, "description": c.description, "inputSchema": c.input_schema}
            for c in TOOL_CONTRACTS
        ]

    def handle(self, name: str, args: dict) -> ToolResult:
        contract = get_tool_contract(name)
        if contract is None:
            return ToolResult(status=ERROR, error=f"未知工具: {name}")

        fn = getattr(self.provider, name, None)
        if fn is None:
            return ToolResult(status=ERROR, error=f"当前引擎不支持操作: {name}")

        args = args or {}
        try:
            data = fn(args)
            self._record(name, args, data)
            return ToolResult(status=OK, data=data)
        except ProviderError as exc:
            return ToolResult(status=ERROR, error=str(exc))
        except KeyError as exc:
            return ToolResult(status=ERROR, error=f"缺少参数: {exc}")
        except Exception as exc:  # noqa: BLE001 边界兜底，避免打崩入口
            return ToolResult(status=ERROR, error=repr(exc))

    def _record(self, operation: str, params: dict, result) -> None:
        target = params.get("target_path")
        record = Record(
            id=self.store.new_id(),
            target=os.path.abspath(target) if target else "",
            operation=operation,
            parameters=params,
            result=result,
        )
        self.store.record(record)
        self.store.record_call({
            "time": time.time(),
            "operation": operation,
            "parameters": params,
            "record_id": record.id,
        })