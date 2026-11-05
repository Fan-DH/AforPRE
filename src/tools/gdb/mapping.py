# -*- coding: utf-8 -*-
"""gdb_map_address：Ghidra 静态地址与运行时地址的互译（跨引擎组合工具）。

运行时基址来自会话内 gdb 的进程映射；静态基址来自 Ghidra 分析结果
（懒加载：仅本工具需要 Ghidra，Ghidra 缺失时只影响本工具）。
"""

from __future__ import annotations

import json
import os

from contracts.results import ToolResult
from tools.base import ProviderError
from tools.gdb import session
from tools.gdb.common import GENERAL_LIMITATIONS, result, rpc, session_dir

STATIC_INFO_FILE = "static_info.json"


def _static_image_base(provider, session_directory: str, target: str) -> str:
    """从 Ghidra project 获取静态 image base，并在会话目录缓存。"""
    cache_path = os.path.join(session_directory, STATIC_INFO_FILE)
    try:
        with open(cache_path, "r", encoding="utf-8") as fh:
            cached = json.loads(fh.read())
        if isinstance(cached, dict) and cached.get("image_base") and cached.get("target") == target:
            return cached["image_base"]
    except (OSError, ValueError):
        pass
    from tools.ghidra.runner import GhidraRunner  # 懒加载：地址互译需要 Ghidra 静态分析
    runner = GhidraRunner(provider.config.workspace)
    payload = runner.run_script(target, "debug_image_base.py", {}, read_only=True)
    image_base = payload.get("image_base")
    if not image_base:
        raise ProviderError("Ghidra 未返回有效的 image base",
                            limitations=["静态地址与运行时地址互译没有完成。"])
    try:
        with open(cache_path, "w", encoding="utf-8") as fh:
            json.dump({"target": target, "image_base": image_base,
                       "language": payload.get("language"),
                       "format": payload.get("executable_format")},
                      fh, ensure_ascii=False)
    except OSError:
        pass
    return image_base


def gdb_map_address(provider, args: dict) -> ToolResult:
    session_id = args["session_id"]
    directory = session_dir(provider, session_id)
    meta = session.read_session_state(provider.config.workspace, session_id)
    target = meta.get("target")
    if not target or not os.path.isfile(target):
        raise ProviderError(
            "该会话没有可用的本地目标文件（attach/connect 未提供 target_path），无法获取静态基址；"
            "attach/connect 时提供与运行程序一致的本地文件作为 target_path。",
            limitations=["静态地址与运行时地址互译没有完成。"])
    try:
        # Ghidra prints hexadecimal addresses without 0x, including leading zeros.
        address = int(args["address"], 16)
    except ValueError as exc:
        raise ProviderError("地址无法解析: %s" % args["address"],
                            limitations=["地址互译没有完成。"]) from exc
    direction = args.get("direction", "static_to_runtime")
    static_base = int(_static_image_base(provider, directory, target), 16)
    mappings = rpc(provider, session_id, "mappings", {}, timeout=20)
    runtime_base = int(mappings["runtime_base"], 16)
    with open(target, "rb") as stream:
        header = stream.read(18)
    pie = (header[:4] == b"\x7fELF" and len(header) == 18 and
           int.from_bytes(header[16:18], "little" if header[5] == 1 else "big") == 3)

    if direction == "static_to_runtime":
        offset = address - static_base
        output = runtime_base + offset
    else:
        offset = address - runtime_base
        output = static_base + offset
    data = {
        "session_id": session_id,
        "direction": direction,
        "input_address": hex(address),
        "output_address": hex(output),
        "offset_from_image_base": hex(offset),
        "static_image_base": hex(static_base),
        "runtime_image_base": hex(runtime_base),
        "module_path": mappings.get("module_path"),
        "pie_detected": pie,
    }
    limitations = list(GENERAL_LIMITATIONS) + [
        "换算基于主模块基址；libc/ld 等共享库地址不适用，请对目标库单独建立会话分析。",
        "静态基址取自 Ghidra 分析结果（首次调用触发一次 analyzeHeadless，结果缓存于会话目录）；"
        "Ghidra 环境不可用时本工具不可用，其余调试工具不受影响。",
        "远端目标无法读取进程映射，本工具不可用（见 gdb_connect 的限制说明）。"]
    if offset < 0:
        limitations.append("换算偏移为负：输入地址低于 image base，结果可能不指向有效代码。")
    return result(data, limitations=limitations)
