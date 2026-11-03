"""命令行入口：直接调用单个工具。

示例：
    python3 src/entrypoints/CLI/cli.py inspect_target --target-path tests/samples/demo
    python3 src/entrypoints/CLI/cli.py search_strings --target-path tests/samples/demo --pattern 'flag\\{'
    python3 src/entrypoints/CLI/cli.py get_xrefs --target-path tests/samples/demo --needle 'flag{...}'
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent.parent.parent)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from config import load_config  # noqa: E402
from entrypoints.dispatcher import ToolDispatcher  # noqa: E402
from records.store import RecordStore  # noqa: E402
from tools.binutils.config import missing_binaries  # noqa: E402
from tools.binutils.main import BinutilsProvider  # noqa: E402

TOOL_NAMES = ["inspect_target", "search_strings", "list_symbols", "get_xrefs"]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="调用单个分析工具")
    parser.add_argument("tool", choices=TOOL_NAMES)
    parser.add_argument("--target-path", dest="target_path")
    parser.add_argument("--pattern")
    parser.add_argument("--min-length", dest="min_length", type=int)
    parser.add_argument("--needle")
    parser.add_argument("--json", action="store_true", help="输出完整 ToolResult JSON")
    args = parser.parse_args(argv)

    missing = missing_binaries()
    if missing:
        print("缺少系统工具: " + ", ".join(missing), file=sys.stderr)
        return 2

    cfg = load_config()
    cfg.ensure_workspace()
    provider = BinutilsProvider(cfg)
    store = RecordStore(cfg.workspace)
    dispatcher = ToolDispatcher(provider, store)

    params = {"target_path": args.target_path}
    if args.pattern is not None:
        params["pattern"] = args.pattern
    if args.min_length is not None:
        params["min_length"] = args.min_length
    if args.needle is not None:
        params["needle"] = args.needle

    result = dispatcher.handle(args.tool, params)
    out = result.to_dict()

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    elif out["status"] == "ok":
        print(json.dumps(out["data"], ensure_ascii=False, indent=2))
    else:
        print(f"错误: {out['error']}", file=sys.stderr)

    return 0 if out["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())