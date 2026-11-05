"""Ghidra 引擎的专属环境校验。

共享配置在 src/config.py；这里只校验本引擎依赖的 Ghidra 是否可用。
引擎信息通过 register_engine 注册到全局注册表，供 check_engines 自动发现。

推荐版本（固定）：Ghidra 11.2.1 + JDK 21
  - 下载页：https://github.com/NationalSecurityAgency/ghidra/releases
  - 安装后设置环境变量 GHIDRA_HOME 指向解压根目录（含 support/ 子目录）
  - 或解压到 .external/ghidra/（Agent 统一下载位置）

查找顺序：
  1. 环境变量 GHIDRA_HOME / GHIDRA_INSTALL_DIR 下的 support/analyzeHeadless
  2. PATH 中的 analyzeHeadless
  3. .external/ghidra/support/analyzeHeadless
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

from tools.engine_info import register_engine, EngineInfo
from tools.ghidra.diagnostics import diagnostic

# 固定推荐的 Ghidra 版本
RECOMMENDED_VERSION = "11.2.1"
RECOMMENDED_JDK = "21"

# 项目根目录（src/tools/ghidra/config.py 往上四级）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
JDK_INSTALL_HINT = "Ghidra 11.x 要求 JDK 21+，下载：https://adoptium.net/temurin/releases/"


def check_decompiler(headless: str | None) -> dict:
    """Inspect the native executable; never repair permissions automatically."""
    system = {"Linux": "linux", "Darwin": "mac", "Windows": "win"}.get(platform.system())
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "x86_64": "x86_64",
            "aarch64": "arm_64", "arm64": "arm_64"}.get(machine, machine)
    target = f"{system}_{arch}" if system else machine
    root = Path(headless).absolute().parent.parent if headless else None
    if headless:
        try:
            root = Path(headless).resolve().parent.parent
        except (OSError, RuntimeError):
            pass
    path = (root / "Ghidra/Features/Decompiler/os" / target /
            ("decompile.exe" if system == "win" else "decompile")) if root else None
    try:
        exists = bool(path and path.is_file())
        permissions = oct(path.stat().st_mode & 0o777) if exists else None
        executable = bool(exists and os.access(path, os.X_OK))
    except OSError as exc:
        return {"name": "decompiler", "available": False, "path": str(path),
                "platform": target, "reason": "unreadable", "error": str(exc),
                "permissions": None,
                "install_hint": "检查 Decompiler 目录和文件的读取/执行权限，获准后修复并重启服务复检。"}
    reason = "ready" if executable else ("not_executable" if exists else "missing")
    return {
        "name": "decompiler", "available": executable, "path": str(path) if path else None,
        "platform": target, "reason": reason,
        "permissions": permissions,
        "install_hint": (
            "检查当前平台的原生 decompile 文件。不可执行时，解压丢失执行位是可能原因；"
            "获准后仅修复该文件的执行权限，或保留权限重新解压。"
            "文件缺失时检查发行包的平台及解压完整性，不要递归 chmod；修复后重启 APRE MCP 服务并复检。"
        ),
    }


def execution_environment(env=None) -> dict:
    """Use one JDK for probing and launch: explicit, bundled, then PATH."""
    values = dict(os.environ if env is None else env)
    home = values.get("JAVA_HOME")
    if not home:
        bundled = os.path.join(external_dir(values), "jdk-21")
        if all(os.path.isfile(os.path.join(bundled, "bin", name)) and
               os.access(os.path.join(bundled, "bin", name), os.X_OK)
               for name in ("java", "javac")):
            home = bundled
            values["JAVA_HOME"] = home
    if home:
        selected = os.path.abspath(os.path.join(home, "bin"))
        entries = values.get("PATH", os.defpath).split(os.pathsep)
        values["PATH"] = os.pathsep.join([selected] + [entry for entry in entries if entry != selected])
    return values


def external_dir(env=None) -> str:
    env = os.environ if env is None else env
    return os.path.abspath(env.get("APRE_EXTERNAL_DIR") or str(_PROJECT_ROOT / ".external"))


def find_analyze_headless(env=None) -> str | None:
    """返回 analyzeHeadless 的绝对路径，找不到则返回 None。"""
    env = os.environ if env is None else env
    for env_var in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR"):
        home = env.get(env_var, "").strip()
        if not home:
            continue
        for sub in (os.path.join("support", "analyzeHeadless"), "analyzeHeadless"):
            candidate = os.path.join(home, sub)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return os.path.abspath(candidate)
    p = shutil.which("analyzeHeadless", path=env.get("PATH", os.defpath))
    if p:
        return os.path.abspath(p)
    # 3. .external/ghidra/support/analyzeHeadless
    candidate = os.path.join(external_dir(env), "ghidra", "support", "analyzeHeadless")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return os.path.abspath(candidate)
    return None


def is_available() -> bool:
    """只探测启动器是否已安装；运行态由实际 Runner 校验。"""
    return find_analyze_headless() is not None


def _check_jdk(env=None) -> dict:
    """检查 JDK 是否可用且版本 >= 21（Ghidra 11.x 要求）。"""
    env = execution_environment(env)
    try:
        java_home = env.get("JAVA_HOME")
        java = (os.path.join(java_home, "bin", "java") if java_home else
                shutil.which("java", path=env.get("PATH", os.defpath)))
        javac = (os.path.join(java_home, "bin", "javac") if java_home else
                 shutil.which("javac", path=env.get("PATH", os.defpath)))
        if not java or not javac:
            return {"available": False, "version": None, "sufficient": False,
                    "error": "未从 JAVA_HOME、自带 jdk-21 或 PATH 找到 java 和 javac",
                    "java_path": java, "javac_path": javac}
        result = subprocess.run(
            [java, "-version"],
            capture_output=True, text=True, timeout=5, env=env,
        )
        output = result.stderr or result.stdout or ""
        compiler = subprocess.run([javac, "-version"], capture_output=True,
                                  text=True, timeout=5, env=env)
        if result.returncode or compiler.returncode:
            return {"available": False, "version": None, "sufficient": False,
                    "error": "Java 版本检查命令执行失败",
                    "java_path": java, "javac_path": javac,
                    "java_returncode": result.returncode, "javac_returncode": compiler.returncode,
                    "java_output": output[-2000:],
                    "javac_output": (compiler.stdout + compiler.stderr)[-2000:]}
        m = re.search(r'(?:version\s+"|openjdk\s+)(\d+)', output)
        if m:
            major = int(m.group(1))
            # JDK 8 之前的版本号格式是 1.x，需要特殊处理
            if major == 1:
                m2 = re.search(r'version "1\.(\d+)', output)
                major = int(m2.group(1)) if m2 else 0
            cm = re.search(r"javac\s+(\d+)", compiler.stdout or compiler.stderr or "")
            compiler_major = int(cm.group(1)) if cm else 0
            return {"available": True, "version": major,
                    "java_path": os.path.abspath(java), "javac_path": os.path.abspath(javac),
                    "compiler_version": compiler_major,
                    "sufficient": major >= 21 and compiler_major >= 21}
        return {"available": True, "version": "unknown", "sufficient": False,
                "error": "无法解析 Java 版本，未确认版本要求满足",
                "java_path": java, "javac_path": javac, "java_output": output[-2000:]}
    except Exception as exc:
        return {"available": False, "version": None, "sufficient": False,
                "error": str(exc), "exception_type": type(exc).__name__}


def _file_identity(path):
    if not path:
        return None
    try:
        stat = os.stat(path)
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
    except OSError:
        return None


def probe_environment(env=None) -> dict:
    """One coherent installation probe, shared by the registry and Runner."""
    env = execution_environment(env)
    headless = find_analyze_headless(env)
    jdk = {"name": "jdk", **_check_jdk(env), "install_hint": JDK_INSTALL_HINT}
    native = check_decompiler(headless)
    dependencies = [jdk, native]
    missing = [dep["name"] for dep in dependencies
               if not dep["available"] or not dep.get("sufficient", True)]
    diagnostics, limitations = [], []
    for dep in dependencies:
        if dep["name"] in missing:
            message = "%s 未就绪: %s" % (
                dep["name"], dep.get("error") or dep.get("reason") or "版本不满足要求")
            diagnostics.append(diagnostic("ghidra.dependency_" + dep["name"], message,
                                          severity="error", details=dep,
                                          suggestions=[dep["install_hint"]]))
            limitations.append(message + "；不能开始依赖该组件的分析。")
    # Only execution-relevant variables enter the fingerprint, not secrets.
    fingerprint = {
        "env": {name: env.get(name) for name in (
            "GHIDRA_HOME", "GHIDRA_INSTALL_DIR", "APRE_EXTERNAL_DIR", "JAVA_HOME", "PATH",
        )},
        "headless": (headless, _file_identity(headless)),
        "jdk": [(jdk.get(key), _file_identity(jdk.get(key)))
                for key in ("java_path", "javac_path")],
        "versions": [jdk.get("version"), jdk.get("compiler_version"), jdk["available"],
                     jdk.get("sufficient", True)],
        "decompiler": [native["path"], native["available"], native["permissions"],
                       _file_identity(native["path"])],
    }
    return {
        "installed": headless is not None,
        "available": headless is not None and not missing,
        "headless_path": headless,
        "dependencies": dependencies,
        "unavailable_dependencies": missing,
        "environment_fingerprint": hashlib.sha256(
            json.dumps(fingerprint, sort_keys=True).encode("utf-8"),
        ).hexdigest(),
        "diagnostics": diagnostics,
        "limitations": limitations,
    }


def get_install_details() -> dict:
    directory = external_dir()
    return {
        "recommended_version": RECOMMENDED_VERSION,
        "download_url": "https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_11.2.1_build",
        "expected_path": os.path.join(directory, "ghidra", "support", "analyzeHeadless"),
        "external_dir": directory,
        "install_steps": [
            "1. 从 download_url 下载 ghidra_11.2.1_PUBLIC_*.zip",
            "2. 解压并将 Ghidra 目录放到 external_dir/ghidra，或设置 GHIDRA_HOME",
            "3. 确保 JDK 21+ 已安装（java -version 和 javac -version 检查）",
            "4. 在 MCP 客户端的服务启动配置中设置 GHIDRA_HOME，必要时设置 JAVA_HOME",
            "5. 真正停止并重新启动 APRE MCP 服务进程，重新连接后调用 check_engines",
            "6. 确认 server_instance_id 已变化、all_available=true 且 can_continue=true",
        ],
    }


register_engine(EngineInfo(
    name="ghidra",
    prefix="ghidra_",
    is_available=is_available,
    get_details=get_install_details,
    provider_module="tools.ghidra.main",
    provider_class="GhidraProvider",
    probe_environment=probe_environment,
))
