"""MCP stdio 服务器（零第三方依赖的 JSON-RPC 2.0 实现）。

将调度层注册的工具以 MCP 工具形式暴露给外部 Agent。
协议输出写 stdout，诊断日志写 stderr。启动方式：
    python3 src/entrypoints/MCP/mcp_server.py
"""

from __future__ import annotations

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

SERVER_NAME = "apre"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _write(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _result(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


def serve(dispatcher: ToolDispatcher) -> None:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as exc:
            log(f"[apre] 无法解析输入: {exc}")
            continue

        if not isinstance(msg, dict):
            continue

        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}

        # 通知（无 id），例如 notifications/initialized，无需响应
        if "id" not in msg:
            continue

        if method == "initialize":
            client_protocol = params.get("protocolVersion") or PROTOCOL_VERSION
            _write(_result(msg_id, {
                "protocolVersion": client_protocol,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            }))
        elif method == "ping":
            _write(_result(msg_id, {}))
        elif method == "tools/list":
            _write(_result(msg_id, {"tools": dispatcher.list_tools()}))
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            result = dispatcher.handle(name, arguments)
            text = (json.dumps(result.to_dict(), ensure_ascii=False)
                    if result.status == "ok"
                    else f"错误: {result.error}")
            _write(_result(msg_id, {
                "content": [{"type": "text", "text": text}],
                "isError": result.status != "ok",
            }))
        else:
            _write(_error(msg_id, -32601, f"方法不支持: {method}"))


def main() -> int:
    missing = missing_binaries()
    if missing:
        log("[apre] 缺少系统工具: " + ", ".join(missing))
        return 2

    cfg = load_config()
    cfg.ensure_workspace()
    provider = BinutilsProvider(cfg)
    store = RecordStore(cfg.workspace)
    dispatcher = ToolDispatcher(provider, store)

    log(f"[apre] MCP stdio 服务器启动（{SERVER_NAME} {SERVER_VERSION}）")
    serve(dispatcher)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())