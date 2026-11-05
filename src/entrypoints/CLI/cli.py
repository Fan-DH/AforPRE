"""命令行入口：从工具契约生成参数，直接调用单个工具。

示例与样本编译方式见 README.md；每个工具支持 --help 和 --json。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent.parent.parent)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from config import load_config  # noqa: E402
from contracts.tools import TOOL_CONTRACTS  # noqa: E402
from entrypoints.dispatcher import ToolDispatcher  # noqa: E402
from records.store import RecordStore  # noqa: E402
from tools.composite import CompositeProvider  # noqa: E402

def _parse_list_arg(value: str, item_type: str = "integer"):
    """Accept JSON arrays or comma-separated values, including hex bytes."""
    s = value.strip()
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass

    inner = s[1:-1] if s.startswith("[") and s.endswith("]") else s
    items = [p for p in re.split(r"[,\s]+", inner.strip()) if p]
    if item_type == "string":
        return [item.strip("\"'") for item in items]
    try:
        return [int(item, 16) if item.lower().startswith("0x") else int(item, 10)
                for item in items]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("列表中的字节必须为整数") from exc


def _parse_object_arg(value: str) -> dict:
    """Parse JSON object arguments such as the launch tool's --env."""
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError("对象参数必须是 JSON 对象") from exc
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("对象参数必须是 JSON 对象")
    return parsed



def build_parser() -> argparse.ArgumentParser:
    """Generate CLI options from the same contracts published over MCP."""
    parser = argparse.ArgumentParser(
        description="调用单个分析工具（binutils 快速查看 / ghidra 深度分析）",
    )
    parser.add_argument("--json", action="store_true", help="输出完整 ToolResult JSON")
    commands = parser.add_subparsers(dest="tool", required=True)
    for contract in TOOL_CONTRACTS:
        command = commands.add_parser(contract.name, help=contract.description,
                                      description=contract.description)
        command.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                             help="输出完整 ToolResult JSON")
        for key, spec in contract.input_schema["properties"].items():
            options = {"dest": key, "default": argparse.SUPPRESS,
                       "required": key in contract.input_schema.get("required", []),
                       "help": spec.get("description", "")}
            kind = spec["type"]
            if kind == "integer":
                options["type"] = int
            elif kind == "boolean":
                options["action"] = argparse.BooleanOptionalAction
            elif kind == "array":
                item_type = spec["items"]["type"]
                options["type"] = lambda value, t=item_type: _parse_list_arg(value, t)
            elif kind == "object":
                options["type"] = _parse_object_arg
            if "enum" in spec:
                options["choices"] = spec["enum"]
            command.add_argument("--" + key.replace("_", "-"), **options)
    return parser


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "__run_job__":
        # 内部模式：job_submit 的 worker（cli.py __run_job__ <job_dir>）
        if len(argv) != 2:
            print("__run_job__ 需要作业目录参数", file=sys.stderr)
            return 2
        from jobs import run_worker
        return run_worker(argv[1])
    args = build_parser().parse_args(argv)
    try:
        cfg = load_config()
        provider = CompositeProvider.auto_build(cfg)
        dispatcher = ToolDispatcher(provider, RecordStore(cfg.workspace))
    except (ValueError, OSError) as exc:
        print(f"配置或工作目录错误: {exc}", file=sys.stderr)
        return 2
    params = {key: value for key, value in vars(args).items()
              if key not in {"tool", "json"}}

    result = dispatcher.handle(args.tool, params)
    from entrypoints.presentation import present_result
    out = present_result(result, params.get("response_detail", "full"))

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    elif out["status"] == "ok":
        print(json.dumps(out["data"], ensure_ascii=False, indent=2))
    else:
        print(f"错误: {out['error']}", file=sys.stderr)
    if not args.json:
        for limitation in out["limitations"]:
            print(f"限制: {limitation}", file=sys.stderr)
        for diagnostic in out["diagnostics"]:
            if diagnostic.get("severity") == "error":
                print(f"诊断 [{diagnostic['code']}]: "
                      + json.dumps(diagnostic.get("details", {}), ensure_ascii=False), file=sys.stderr)

    return 0 if out["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
