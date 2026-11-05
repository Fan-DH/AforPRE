# -*- coding: utf-8 -*-
"""gdb 引擎的专属环境校验与安装指引。

共享配置在 src/config.py；这里只校验本引擎依赖的 gdb 是否可用。
引擎信息通过 register_engine 注册到全局注册表，供 check_engines 自动发现。

gdb 是可选引擎（required=False）：缺失时不阻断 binutils/Ghidra 静态分析，
仅在 check_engines 的 engines 条目与 optional_missing_engines 中给出安装指引。

查找顺序（probe.py）：
  1. 环境变量 APRE_GDB 指向的 gdb
  2. PATH 中的 gdb
  3. .external/gdb/usr/bin/gdb（Agent 统一下载位置，支持 apt 包解包安装）
"""

from __future__ import annotations

from tools.engine_info import EngineInfo, register_engine
from tools.gdb.probe import external_dir, probe_debugger


def is_available() -> bool:
    """安装探测：只回答 gdb 是否可用（含 Python 3 支持）。"""
    return bool(probe_debugger().get("available"))


def probe_environment(env=None) -> dict:
    """一次连贯的安装探测：gdb 定位、版本、Python 支持与 ptrace 约束。"""
    result = probe_debugger(env)
    result["installed"] = result.get("gdb_path") is not None
    return result


def get_install_details() -> dict:
    directory = external_dir()
    return {
        "gdb_path_env": "APRE_GDB",
        "download_url": "https://www.sourceware.org/gdb/download/",
        "expected_path": "%s/gdb/usr/bin/gdb" % directory,
        "external_dir": directory,
        "install_hint": (
            "优先使用系统包管理器安装：apt install gdb（或 yum install gdb）。"
            "无 root 权限时可下载 gdb 的 .deb 包并解包到 .external/gdb。"
        ),
        "install_steps": [
            "1. 有 root 权限：apt install gdb（需带 Python 3 支持，发行版默认提供）；安装后重启 APRE MCP 服务并复检。",
            "2. 无 root 权限：apt-get download gdb 获取 gdb_*.deb，"
            "dpkg -x gdb_*.deb external_dir/gdb 解包；",
            "3. 按依赖列表同样下载并解包依赖包（apt-cache depends gdb 给出的 Depends，"
            "如 libbabeltrace1、libipt2、libpython3.*、libdebuginfod、libsource-highlight 等）；",
            "4. 解包后执行 python3 src/tools/gdb/bundle.py --prefix external_dir/gdb 完成安装："
            "原始 ELF 保留为 usr/bin/gdb.real，usr/bin/gdb 与 gdb 均成为可搬迁的启动器，"
            "可直接批处理运行，无需手工设置 LD_LIBRARY_PATH 或连接 MCP。"
            "APRE 自动探测解包目录时也会尝试完成此步骤；只读目录需在打包阶段完成；",
            "5. 也可设置 APRE_GDB 指向任意自定义构建（需 Python 3 支持），写入 MCP 客户端服务启动配置；",
            "6. 真正停止并重新启动 APRE MCP 服务进程，重新连接后调用 check_engines，"
            "确认 engines 中 gdb 条目 available=true。",
        ],
        "notes": [
            "gdb 必须带 Python 3 支持（gdb -batch -ex 'python print(1)' 可验证）；精简构建需换用完整包。",
            "动态调试会真实运行目标程序，仅在受控环境中对可信样本使用。",
        ],
    }


register_engine(EngineInfo(
    name="gdb",
    prefix="gdb_",
    is_available=is_available,
    get_details=get_install_details,
    provider_module="tools.gdb.main",
    provider_class="GdbProvider",
    probe_environment=probe_environment,
    required=False,
))
