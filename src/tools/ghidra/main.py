"""Ghidra 引擎的 Provider 主管。

对外暴露统一操作接口（操作名 = 工具名），直接调用对应的 Ghidra 脚本。
生命周期：每个二进制维护一个独立 Ghidra project，首次导入自动分析，
后续操作复用已分析状态；修改类操作持久化到 project。
动态调试由独立的 gdb 引擎提供（tools/gdb，工具前缀 gdb_）。
"""

from __future__ import annotations

import os

from config import Config
from contracts.results import ToolResult
from contracts.tools import get_tool_contract, validate_arguments
from tools.base import ProviderError
from tools.ghidra.runner import GhidraRunner

READ_ONLY_SCRIPTS = {
    "ghidra_inspect": "inspect.py", "ghidra_list_functions": "list_functions.py",
    "ghidra_list_globals": "list_globals.py", "ghidra_decompile": "decompile.py",
    "ghidra_xrefs_to": "xrefs_to.py", "ghidra_xrefs_from": "xrefs_from.py",
    "ghidra_get_strings": "get_strings.py", "ghidra_read_bytes": "read_bytes.py",
    "ghidra_read_string": "read_string.py", "ghidra_get_cfg": "get_cfg.py",
    "ghidra_get_call_graph": "get_call_graph.py", "ghidra_find_crypto": "find_crypto.py",
    "ghidra_disassemble": "disassemble.py",
}

class GhidraProvider:
    def __init__(self, config: Config):
        self.config = config
        self.runner = GhidraRunner(config.workspace)

    def check_environment(self) -> dict:
        return self.runner.check_environment()

    def ghidra_batch(self, args: dict) -> ToolResult:
        operations, invalid = [], {}
        for index, operation in enumerate(args["operations"]):
            name, params = operation["tool_name"], dict(operation["arguments"])
            try:
                if name not in READ_ONLY_SCRIPTS or "target_path" in params:
                    raise ValueError("batch 仅接受同一目标的 Ghidra 只读查询，子参数不能含 target_path")
                validate_arguments(get_tool_contract(name), {"target_path": args["target_path"], **params})
            except ValueError as exc:
                message = f"operations[{index}] ({name}): {exc}"
                invalid[index] = {"index": index, "tool_name": name, "status": "error",
                    "error": message, "data": None, "limitations": ["该项未执行。"],
                    "diagnostics": [{"code": "ghidra.batch_invalid_arguments", "severity": "error",
                        "message": message, "details": {"index": index, "tool_name": name,
                        "allowed_parameters": sorted(get_tool_contract(name).input_schema["properties"])
                            if get_tool_contract(name) else []}, "suggestions": []}]}
                continue
            if name == "ghidra_get_strings":
                params.setdefault("min_length", self.config.min_string_len)
            params.pop("response_detail", None)
            operations.append({"index": index, "tool_name": name,
                               "script": READ_ONLY_SCRIPTS[name], "arguments": params})
        result = (self.run_operation({"target_path": args["target_path"], "operations": operations}, "batch.py")
                  if operations else ToolResult(data={"results": []}))
        by_index = {item["index"]: item for item in result.data["results"]}
        by_index.update(invalid)
        result.data["results"] = [by_index[i] for i in range(len(args["operations"]))]
        result.data["all_succeeded"] = all(item["status"] == "ok" for item in result.data["results"])
        if not result.data["all_succeeded"]:
            result.status = "error"
            result.error = "部分 Ghidra 查询失败，详见 data.results；成功查询的结果仍可使用。"
            result.diagnostics.append({"code": "ghidra.batch_partial_failure", "severity": "error",
                                       "message": result.error, "details": {}, "suggestions": []})
        return result

    def run_operation(self, args: dict, script: str, *, read_only: bool = True) -> ToolResult:
        """Shared adapter; validation belongs to the dispatcher contract."""
        path = os.path.abspath(args["target_path"])
        params = {key: value for key, value in args.items() if key != "target_path"}
        if script == "get_strings.py":
            params.setdefault("min_length", self.config.min_string_len)
        payload = self.runner.run_script(path, script, params, read_only=read_only)
        return ToolResult(
            data={key: value for key, value in payload.items() if not key.startswith("_")},
            limitations=payload.get("_limitations", []),
            diagnostics=payload.get("_diagnostics", []),
        )

    def ghidra_apply_memory(self, args: dict) -> ToolResult:
        from tools.ghidra.memory import apply_memory
        return apply_memory(self, args)

    # --- 信息类 ---
    def ghidra_inspect(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'inspect.py')

    def ghidra_list_functions(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'list_functions.py')

    def ghidra_list_globals(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'list_globals.py')

    # --- 反编译类 ---
    def ghidra_decompile(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'decompile.py')

    # --- 交叉引用类 ---
    def ghidra_xrefs_to(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'xrefs_to.py')

    def ghidra_xrefs_from(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'xrefs_from.py')

    # --- 数据类 ---
    def ghidra_get_strings(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'get_strings.py')

    def ghidra_read_bytes(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'read_bytes.py')

    def ghidra_read_string(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'read_string.py')

    def ghidra_define_string(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'define_string.py', read_only=False)

    # --- 控制流类 ---
    def ghidra_get_cfg(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'get_cfg.py')

    def ghidra_get_call_graph(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'get_call_graph.py')

    # --- 修改类 ---
    def ghidra_rename_symbol(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'rename_symbol.py', read_only=False)

    def ghidra_set_signature(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'set_signature.py', read_only=False)

    def ghidra_create_function(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'create_function.py', read_only=False)

    def ghidra_patch_bytes(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'patch_bytes.py', read_only=False)

    def ghidra_add_comment(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'add_comment.py', read_only=False)

    # --- 高级分析类 ---
    def ghidra_find_crypto(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'find_crypto.py')

    def ghidra_disassemble(self, args: dict) -> ToolResult:
        return self.run_operation(args, 'disassemble.py')

    # --- project 管理 ---
    def ghidra_reset_project(self, args: dict) -> ToolResult:
        path = os.path.abspath(args["target_path"])
        return ToolResult(data=self.runner.reset_project(path), limitations=[
            "重置仅处理当前文件内容 hash 对应的项目，不删除其他目标或旧格式缓存。"
        ])

