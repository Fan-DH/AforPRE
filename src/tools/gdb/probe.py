# -*- coding: utf-8 -*-
"""gdb 引擎的环境探测：定位可用的 gdb 并检查其 Python 支持。

查找顺序（与 analyzeHeadless 的查找风格一致）：
  1. 环境变量 APRE_GDB（显式指定 gdb 路径）
  2. PATH 中的 gdb
  3. .external/gdb/usr/bin/gdb（Agent 统一下载位置）

动态调试不要求 Ghidra 参与执行（gdb 独立驱动目标进程）；
Ghidra 静态分析仅在 gdb_map_address 中提供静态基址。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from tools.gdb.bundle import prepare_bundle

# 项目根目录（src/tools/gdb/probe.py 往上三级）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent

GDB_INSTALL_HINT = (
    "安装 gdb（需支持 Python 3，如 apt install gdb），或设置 APRE_GDB 指向"
    "自定义 gdb；解包版可运行 python3 src/tools/gdb/bundle.py 完成独立启动器安装。"
)

_PTRACE_SCOPE_NOTES = {
    0: "attach 不受限制。",
    1: "仅允许附加到本进程的子孙进程；附加其他进程需要 CAP_SYS_PTRACE（常见限制，如 root 或相应配置）。",
    2: "仅允许具有 CAP_SYS_PTRACE 的进程附加。",
    3: "禁止附加任何进程（需调整内核参数后重启）。",
}


def external_dir(env=None) -> str:
    env = os.environ if env is None else env
    return os.path.abspath(env.get("APRE_EXTERNAL_DIR") or str(_PROJECT_ROOT / ".external"))


def _external_gdb_libdirs(prefix: str) -> list[str]:
    """收集解包版 gdb 前缀下的动态库目录（usr/lib/<arch> 与 lib/<arch>）。"""
    libdirs = []
    for base in ("usr/lib", "lib", "usr/lib64", "lib64"):
        base_path = os.path.join(prefix, base)
        try:
            entries = sorted(os.listdir(base_path))
            libdirs.append(base_path)
        except OSError:
            continue
        for entry in entries:
            candidate = os.path.join(base_path, entry)
            if os.path.isdir(candidate):
                libdirs.append(candidate)
    return libdirs


def ensure_external_gdb_wrapper(env=None) -> str | None:
    """完成解包版安装，使 usr/bin/gdb 与 gdb 均可独立执行。

    只读或非标准安装无法生成启动器时，由调用方退回环境注入。
    """
    prefix = os.path.join(external_dir(env), "gdb")
    try:
        return prepare_bundle(prefix)
    except (OSError, ValueError):
        return None


def gdb_spawn_env(gdb_path: str, env=None) -> dict:
    """返回运行 gdb 所需的子进程环境（含解包版所需的 LD_LIBRARY_PATH）。

    包装脚本可用时无需注入；显式使用原始 usr/bin/gdb 或包装生成失败时，
    把前缀内库目录注入 LD_LIBRARY_PATH，保证 gdb 及会话进程可独立运行。
    """
    env = dict(os.environ if env is None else env)
    prefix = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(gdb_path))))
    # gdb_path 形如 <external>/gdb/usr/bin/gdb 时 prefix = <external>/gdb
    if not (os.path.basename(prefix) == "gdb" and
            os.path.isfile(os.path.join(prefix, "usr", "bin", "gdb"))):
        return env
    with open(gdb_path, "rb") as stream:
        if stream.read(4) != b"\x7fELF":
            return env  # 已完成安装的启动器自行设置库路径
    libdirs = _external_gdb_libdirs(prefix)
    if not libdirs:
        return env
    existing = env.get("LD_LIBRARY_PATH")
    env["LD_LIBRARY_PATH"] = ":".join(libdirs) + (":" + existing if existing else "")
    return env


def find_gdb(env=None) -> str | None:
    """返回可执行 gdb 的绝对路径，找不到则返回 None。"""
    env = os.environ if env is None else env
    explicit = env.get("APRE_GDB", "").strip()
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return os.path.abspath(explicit)
        return None
    found = shutil.which("gdb", path=env.get("PATH", os.defpath))
    if found:
        return os.path.abspath(found)
    # 外置解包版：优先使用自动生成的包装脚本（自带 LD_LIBRARY_PATH），
    # 生成失败时退回原始二进制并由 gdb_spawn_env 注入库路径。
    wrapper = ensure_external_gdb_wrapper(env)
    if wrapper:
        return wrapper
    candidate = os.path.join(external_dir(env), "gdb", "usr", "bin", "gdb")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return os.path.abspath(candidate)
    return None


def _run_gdb(gdb: str, args: list[str], timeout: int = 8, env=None) -> tuple[int, str, str]:
    """运行 gdb 子进程并收集输出；不把任何失败静默吞掉。"""
    proc = subprocess.run(
        [gdb, "-q", "--nx", "-batch"] + args,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, env=gdb_spawn_env(gdb, env),
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _read_ptrace_scope() -> dict:
    path = "/proc/sys/kernel/yama/ptrace_scope"
    try:
        raw = Path(path).read_text(encoding="ascii").strip()
        scope = int(raw)
    except (OSError, ValueError):
        return {"path": path, "readable": False, "scope": None,
                "note": "无法读取 yama ptrace_scope；attach 权限以实际内核配置为准。"}
    return {"path": path, "readable": True, "scope": scope,
            "note": _PTRACE_SCOPE_NOTES.get(scope, "未知的 ptrace_scope 取值；attach 权限以实际内核配置为准。")}


def probe_debugger(env=None) -> dict:
    """探测当前环境中可用的 gdb 及其动态调试能力。

    返回 dict（不抛异常）：available 表示可以开始动态调试会话；
    probe 不缓存结果，每次调用都反映当前环境。
    """
    gdb = find_gdb(env)
    if not gdb:
        return {
            "available": False, "gdb_path": None, "version": None,
            "python_supported": False, "python_version": None,
            "reason": "gdb_not_found",
            "error": "未找到可执行的 gdb（检查 APRE_GDB、PATH 或 .external/gdb/usr/bin/gdb）。",
            "install_hint": GDB_INSTALL_HINT,
        }
    version, python_supported, python_version = None, False, None
    errors = []
    try:
        code, out, err = _run_gdb(gdb, ["--version"], env=env)
        text = (out + "\n" + err).strip()
        match = re.search(r"GNU gdb[^\n]*?(\d+(?:\.\d+)+)", text)
        version = match.group(1) if match else (text.splitlines()[0] if text else None)
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append("gdb --version 探测失败: %s" % exc)
    try:
        code, out, err = _run_gdb(gdb, [
            "-ex", "python import sys; print('APRE_PY%d.%d' % (sys.version_info[0], sys.version_info[1]))",
        ], env=env)
        match = re.search(r"APRE_PY(\d+)\.(\d+)", out + "\n" + err)
        if match:
            python_supported = True
            python_version = "%s.%s" % (match.group(1), match.group(2))
        else:
            errors.append("gdb 未报告 Python 支持（输出: %s）" % (err or out).strip()[-200:])
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append("gdb Python 探测失败: %s" % exc)
    if not python_supported:
        errors.append("gdb 必须带 Python 3 支持（发行版 gdb 默认提供；精简构建可能缺失）。")
    ptrace = _read_ptrace_scope()
    available = bool(gdb) and python_supported and not errors
    return {
        "available": available, "gdb_path": gdb, "version": version,
        "python_supported": python_supported, "python_version": python_version,
        "ptrace_scope": ptrace["scope"], "ptrace_scope_path": ptrace["path"],
        "ptrace_scope_readable": ptrace["readable"], "attach_note": ptrace["note"],
        "reason": "ready" if available else "gdb_incomplete",
        "error": None if available else "；".join(errors) or "gdb 不可用",
        "install_hint": GDB_INSTALL_HINT,
    }
