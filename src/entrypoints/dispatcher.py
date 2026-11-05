"""工具调度：按工具名执行操作并记录，CLI 与 MCP 共享。

工具清单来自 contracts.tools；执行委托给注入的引擎 provider；
每次操作产生一条操作级 Record 写入 records。
"""

from __future__ import annotations

import os
import time

from contracts.record import Record
from contracts.results import ERROR, ToolResult
from contracts.tools import TOOL_CONTRACTS, get_tool_contract, validate_arguments
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
        args = {} if args is None else args
        phase = "validation"
        try:
            contract = get_tool_contract(name)
            if contract is None:
                raise ValueError(f"未知工具: {name}")
            validate_arguments(contract, args)
            fn = getattr(self.provider, name, None)
            if not callable(fn):
                raise ValueError(f"当前引擎不支持操作: {name}")
            phase = "execution"
            data = fn({key: value for key, value in args.items() if key != "response_detail"})
            if isinstance(data, ToolResult):
                result = data
            else:
                result = ToolResult(
                    data=data,
                    limitations=list(data.get("limitations", [])) if isinstance(data, dict) else [],
                    diagnostics=list(data.get("diagnostics", [])) if isinstance(data, dict) else [],
                )
        except ProviderError as exc:
            result = ToolResult(status=exc.status, error=str(exc), data=exc.data,
                                limitations=list(exc.limitations), diagnostics=list(exc.diagnostics))
        except (KeyError, ValueError) as exc:
            result = self._boundary_error(name, phase, exc)
        except Exception as exc:  # noqa: BLE001 边界兜底，避免打崩入口
            result = self._boundary_error(name, phase, exc)
        if result.status != "ok" and not result.limitations:
            result.limitations.append(f"未完成 {name}，没有可作为完整操作结果使用的输出。")
        if result.status != "ok" and not result.diagnostics:
            result.diagnostics.append({"code": "tool.error", "severity": "error",
                "message": result.error or "Tool failed without a message", "details": {"operation": name},
                "suggestions": ["Read limitations and the current operation record."]})
        try:
            result.record_id = self._record(name, args, result)
        except Exception as exc:
            # An executed mutation must not be reported as a provider failure
            # merely because its audit log could not be written.
            result.limitations.append(f"记录写入失败: {exc}")
            result.diagnostics.append({"code": "records.write_failed", "severity": "warning",
                "message": str(exc), "details": {"operation": name, "record_id": result.record_id},
                "suggestions": ["检查 APRE_WORKSPACE 权限和磁盘空间；不要因日志失败盲目重试已执行的修改。"]})
        return result

    @staticmethod
    def _boundary_error(name, phase, exc) -> ToolResult:
        limitation = (f"未执行 {name}：输入或工具契约校验失败。" if phase == "validation" else
                      f"未完成 {name}：执行出现异常；修改类调用不能据此假定已经回滚。")
        return ToolResult(
            status=ERROR, error=str(exc),
            limitations=[limitation],
            diagnostics=[{"code": f"dispatcher.{phase}_failed", "severity": "error",
                          "message": str(exc), "details": {"exception_type": type(exc).__name__},
                          "suggestions": ["检查参数和当前操作记录；执行异常需要结合引擎诊断确认原因。"]}],
        )

    def _record(self, operation: str, params, result: ToolResult) -> str:
        parameters = params if isinstance(params, dict) else {"invalid_arguments": params}
        target = parameters.get("target_path")
        record = Record(
            id=self.store.new_id(),
            target=os.path.abspath(target) if isinstance(target, str) and target else "",
            operation=operation,
            parameters=parameters,
            result=result.to_dict(),
            limitations=list(result.limitations),
        )
        record.result["record_id"] = record.id
        self.store.record(record)
        result.record_id = record.id
        self.store.record_call({
            "time": time.time(),
            "operation": operation,
            "parameters": parameters,
            "record_id": record.id,
            "status": result.status,
        })
        return record.id
