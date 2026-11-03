"""工具清单：面向 Agent 的动作声明（name / description / inputSchema）。

工具名即引擎的操作名，调度层按此名路由到引擎实现。
注意：契约是跨引擎共享的，这里的清单表达的是「本项目支持哪些动作」，
不绑定 binutils 还是 ghidra。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolContract:
    name: str
    description: str
    input_schema: dict


TOOL_CONTRACTS: list[ToolContract] = [
    ToolContract(
        name="inspect_target",
        description="检查 ELF 文件概览：格式（ELF32/64）、架构、类型、入口点与节表。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "ELF 文件的绝对或相对路径"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="search_strings",
        description="提取并筛选 ELF 中的可打印静态字符串；pattern 是正则，忽略大小写。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "pattern": {"type": "string", "description": "可选正则，例如 flag"},
                "min_length": {"type": "integer", "description": "最小字符串长度，默认 4"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="list_symbols",
        description="列出已定义符号（按地址排序），用于定位函数与全局对象。",
        input_schema={
            "type": "object",
            "properties": {"target_path": {"type": "string"}},
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="get_xrefs",
        description="查找反汇编中对某个字符串内容的引用（返回引用行）。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "needle": {"type": "string", "description": "要查找引用的字符串内容"},
            },
            "required": ["target_path", "needle"],
        },
    ),
]


def get_tool_contract(name: str) -> ToolContract | None:
    for contract in TOOL_CONTRACTS:
        if contract.name == name:
            return contract
    return None