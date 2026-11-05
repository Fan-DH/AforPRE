"""引擎信息注册表：环境校验的解耦核心。

每个引擎在自己的 config.py 中调用 register_engine() 注册环境信息
（可用性检查、下载指引、Provider 工厂入口等）。
auto_discover() 自动扫描 tools/ 下的引擎目录并触发注册。
check_all_engines() 将注册信息与当前服务的实际 Provider 运行态合并。

添加新引擎时，只需在 tools/<new_engine>/config.py 中调用 register_engine()，
不需要修改本文件或任何入口代码。
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


@dataclass
class Dependency:
    """引擎的外部依赖（如 JDK）。"""
    name: str
    check: Callable[[], dict]       # 返回 {"available": bool, "version": ..., ...}
    install_hint: str = ""


@dataclass
class EngineInfo:
    """引擎环境信息：供注册表收集与 check_engines 返回。"""
    name: str                       # 引擎名（如 "binutils"）
    prefix: str | None              # 工具名前缀（None 或 "ghidra_"）
    is_available: Callable[[], bool]
    get_details: Callable[[], dict]  # 缺失时的详情（下载 URL、安装步骤等）
    provider_module: str            # Provider 类所在模块（如 "tools.binutils.main"）
    provider_class: str             # Provider 类名（如 "BinutilsProvider"）
    dependencies: list[Dependency] = field(default_factory=list)
    probe_environment: Callable[[], dict] | None = None
    required: bool = True           # False 表示可选能力：缺失不阻断其他引擎分析


# ── 全局注册表 ──────────────────────────────────────────────
_REGISTRY: list[EngineInfo] = []


def register_engine(info: EngineInfo) -> None:
    """注册一个引擎的环境信息（各引擎 config.py 在 import 时调用）。"""
    for index, registered in enumerate(_REGISTRY):
        if registered.name == info.name:
            _REGISTRY[index] = info
            return
    _REGISTRY.append(info)


def get_all_engines() -> list[EngineInfo]:
    """返回所有已注册引擎的信息。"""
    return list(_REGISTRY)


def auto_discover() -> None:
    """自动扫描 tools/ 下的引擎目录，import 各 config 模块触发注册。

    扫描条件：tools/ 下的子目录，含 __init__.py，且不以 _ 开头。
    每个目录的 config.py 中应调用 register_engine() 完成注册。
    """
    tools_dir = Path(__file__).resolve().parent
    for entry in sorted(tools_dir.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name.startswith("_"):
            continue
        if not (entry / "__init__.py").exists() or not (entry / "config.py").exists():
            continue
        module_name = "tools.%s.config" % entry.name
        # A broken engine import is a programming error, not a missing engine.
        importlib.import_module(module_name)


def probe_engine(info: EngineInfo) -> dict:
    """Installation-only probe; it cannot certify an existing Provider."""
    if info.probe_environment is not None:
        return info.probe_environment()
    installed = info.is_available()
    deps = []
    for dep in info.dependencies:
        entry = {"name": dep.name, **dep.check()}
        if dep.install_hint:
            entry["install_hint"] = dep.install_hint
        deps.append(entry)
    missing = [
        dep["name"] for dep in deps
        if not dep.get("available", False) or not dep.get("sufficient", True)
    ]
    return {"installed": installed, "available": installed and not missing,
            "dependencies": deps, "unavailable_dependencies": missing}


def check_all_engines(providers: dict[str, object] | None = None) -> dict:
    """Check the actual service Providers, not just installed binaries.

    必选引擎（required=True）共同决定 all_available/can_continue 与 agent_action；
    可选引擎（required=False）缺失时不阻断分析，只在 engines 条目和
    optional_missing_engines 中报告安装指引。
    """
    auto_discover()
    providers = {} if providers is None else providers
    engines = []
    for info in _REGISTRY:
        provider = providers.get(info.name)
        runtime_check = getattr(provider, "check_environment", None)
        if callable(runtime_check):
            entry = runtime_check()
        else:
            entry = probe_engine(info)
            entry["detected_available"] = entry["available"]
            entry["available"] = provider is not None and entry["available"]
            entry["runtime"] = {
                "available": entry["available"],
                "restart_required": provider is None,
                "reason": "provider_not_registered" if provider is None else
                          ("ready" if entry["available"] else "environment_unavailable"),
            }
        entry["name"] = info.name
        entry["required"] = info.required
        if not entry["detected_available"]:
            entry.update(info.get_details())
        engines.append(entry)

    required_engines = [e for e in engines if e["required"]]
    all_available = bool(required_engines) and all(e["available"] for e in required_engines)
    detected_all_available = bool(required_engines) and all(e["detected_available"] for e in required_engines)
    blocked_engines = [e["name"] for e in required_engines if not e["available"]]
    missing_engines = [e["name"] for e in required_engines if not e["detected_available"]]
    optional_missing_engines = [e["name"] for e in engines
                                if not e["required"] and not e["detected_available"]]
    restart_engines = [e["name"] for e in engines if e["runtime"]["restart_required"]]
    if missing_engines:
        action = "stop_and_ask_user"
        instructions = (
            "立即停止当前分析，不得切换工具或引擎绕过环境问题。"
            "说明缺失或不满足要求的引擎及依赖，并询问安装或修复许可；"
            "用户明确同意前，不得下载、安装或更改环境。拒绝时保持停止。"
            "获准后按 install_steps 或 install_hint 操作。"
            "环境配置必须写入 MCP 客户端的服务启动配置；其他终端的 export 不会改变当前服务。"
            "安装或修复后真正停止并重新启动 APRE MCP 服务进程，再重新连接并调用 check_engines。"
            "确认 server_instance_id 与旧实例不同、all_available=true 且 can_continue=true 后才可恢复。"
            "刷新工具列表、重置 Ghidra project 或重复检查均不等于重启；无权限时请用户执行。"
        )
    elif not all_available:
        action = "restart_server"
        instructions = (
            "安装探测已通过，但当前服务的 Provider 运行态未就绪或已过期。"
            "保持停止，不要重新安装，也不要尝试分析工具。"
            "通过 MCP 客户端真正停止并重新启动 APRE MCP 服务进程，使用正确的启动环境重新连接。"
            "再次调用 check_engines，确认 server_instance_id 已变化、"
            "all_available=true 且 can_continue=true 后才可恢复。"
            "仅刷新工具列表或重复检查不会更新当前 Provider；引擎注册在新服务启动时同步完成，无需盲目等待。"
            "无法操作客户端的服务控制时，请用户重启并等待重新连接，不得声称已完成。"
        )
    else:
        action = "continue"
        instructions = "当前 APRE 服务的 Provider 运行态检查通过，可以继续分析。"
    if optional_missing_engines:
        instructions += (
            " 可选能力未就绪：%s（不影响静态分析；确需使用前，按 engines 中该引擎的"
            " install_steps 安装，获准后重启 APRE MCP 服务并复检）。" % "、".join(optional_missing_engines)
        )
    return {
        "environment_scope": "current_server_process",
        "engines": engines,
        "all_available": all_available,
        "detected_all_available": detected_all_available,
        "blocked_engines": blocked_engines,
        "missing_engines": missing_engines,
        "optional_missing_engines": optional_missing_engines,
        "restart_engines": restart_engines,
        "can_continue": all_available,
        "requires_user_confirmation": bool(missing_engines),
        "restart_required": bool(restart_engines),
        "restart_required_after_install": not all_available,
        "agent_action": action,
        "limitations": [item for entry in engines for item in entry.get("limitations", [])],
        "diagnostics": [item for entry in engines for item in entry.get("diagnostics", [])],
        "user_prompt": (
            "APRE 环境未就绪（%s），分析已暂停。是否允许安装或修复这些引擎及其依赖，"
            "并在完成后重启 APRE MCP 服务？" % "、".join(missing_engines)
        ) if missing_engines else "",
        "instructions": instructions,
        "restart_hint": (
            "真正停止并重新启动 APRE MCP 服务，继承正确的启动环境；重新连接后调用 check_engines，"
            "确认 server_instance_id 已变化、all_available=true 且 can_continue=true。"
        ) if not all_available else "",
    }
