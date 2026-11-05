"""MCP stdio 服务器

将调度层注册的工具以 MCP 工具形式暴露给外部 Agent。
将 src/skills 下的 Markdown 文档以只读 MCP Resource 暴露。
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
from entrypoints.presentation import present_result  # noqa: E402
from entrypoints.MCP.resources import SkillResources  # noqa: E402
from entrypoints.dispatcher import ToolDispatcher  # noqa: E402
from records.store import RecordStore  # noqa: E402
from tools.composite import CompositeProvider  # noqa: E402

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


def serve(dispatcher: ToolDispatcher, resources: SkillResources | None = None) -> None:
    resources = resources if resources is not None else SkillResources()
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as exc:
            log(f"[apre] 无法解析输入: {exc}")
            _write(_error(None, -32700, "无法解析 JSON"))
            continue

        if not isinstance(msg, dict):
            _write(_error(None, -32600, "请求必须是对象，不支持批量请求"))
            continue
        if msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            _write(_error(msg.get("id"), -32600, "无效的 JSON-RPC 请求"))
            continue

        method = msg.get("method")
        msg_id = msg.get("id")
        if "id" in msg and (isinstance(msg_id, bool) or
                           not isinstance(msg_id, (str, int))):
            _write(_error(None, -32600, "id 必须是字符串或整数"))
            continue
        params = msg.get("params", {})
        if params is None:
            params = {}

        # 通知（无 id），例如 notifications/initialized，无需响应
        if "id" not in msg:
            continue

        if not isinstance(params, dict):
            _write(_error(msg_id, -32602, "params 必须是对象"))
            continue

        if method == "initialize":
            _write(_result(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            }))
        elif method == "ping":
            _write(_result(msg_id, {}))
        elif method == "tools/list":
            if params.get("cursor") is not None:
                _write(_error(msg_id, -32602, "工具列表为单页，不接受 cursor"))
                continue
            _write(_result(msg_id, {"tools": dispatcher.list_tools()}))
        elif method == "resources/list":
            if params.get("cursor") is not None:
                _write(_error(msg_id, -32602, "资源列表为单页，不接受 cursor"))
                continue
            try:
                _write(_result(msg_id, {"resources": resources.list_resources()}))
            except (OSError, UnicodeError) as exc:
                log(f"[apre] 无法列举 Skill 资源: {exc}")
                _write(_error(msg_id, -32603, "无法列举 Skill 资源"))
        elif method == "resources/templates/list":
            _write(_result(msg_id, {"resourceTemplates": []}))
        elif method == "resources/read":
            uri = params.get("uri")
            if not isinstance(uri, str) or not uri:
                _write(_error(msg_id, -32602, "uri 必须是非空字符串"))
                continue
            try:
                content = resources.read_resource(uri)
                _write(_result(msg_id, {"contents": [content]}))
            except FileNotFoundError:
                _write(_error(msg_id, -32002, "Skill 资源不存在"))
            except (OSError, UnicodeError) as exc:
                log(f"[apre] 无法读取 Skill 资源: {exc}")
                _write(_error(msg_id, -32603, "无法读取 Skill 资源"))
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not name or not isinstance(arguments, dict):
                _write(_error(msg_id, -32602, "name 必须是非空字符串，arguments 必须是对象"))
                continue
            result = dispatcher.handle(name, arguments)
            text = json.dumps(present_result(result, arguments.get("response_detail", "compact")), ensure_ascii=False)
            _write(_result(msg_id, {
                "content": [{"type": "text", "text": text}],
                "isError": result.status != "ok",
            }))
        else:
            _write(_error(msg_id, -32601, f"方法不支持: {method}"))


def main() -> int:
    try:
        cfg = load_config()
        provider = CompositeProvider.auto_build(cfg)
        store = RecordStore(cfg.workspace)
    except (ValueError, OSError) as exc:
        log(f"[apre] 配置或工作目录错误: {exc}")
        return 2

    env = provider.check_engines({})
    for e in env["engines"]:
        status = "已启用" if e["available"] else "不可用"
        log("[apre] %s 引擎: %s" % (e["name"], status))
    if not env["all_available"]:
        log("[apre] Agent 可调用 check_engines 工具获取安装指引")

    dispatcher = ToolDispatcher(provider, store)

    log(f"[apre] MCP stdio 服务器启动（{SERVER_NAME} {SERVER_VERSION}，"
        f"instance={env['server_instance_id']}，pid={env['server_pid']}）")
    serve(dispatcher)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
