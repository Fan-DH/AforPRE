"""binutils 引擎的专属环境校验。

共享配置在 src/config.py；这里只校验本引擎依赖的系统二进制是否齐全。
引擎信息通过 register_engine 注册到全局注册表，供 check_engines 自动发现。
"""

from __future__ import annotations

import shutil

from tools.engine_info import register_engine, EngineInfo

REQUIRED_BINARIES = ("readelf", "strings", "nm", "objdump")


def missing_binaries() -> list[str]:
    """返回系统里缺失的 binutils 工具名。"""
    return [name for name in REQUIRED_BINARIES if shutil.which(name) is None]


register_engine(EngineInfo(
    name="binutils",
    prefix=None,
    is_available=lambda: len(missing_binaries()) == 0,
    get_details=lambda: {
        "missing": missing_binaries(),
        "required": list(REQUIRED_BINARIES),
        "install_hint": "apt install binutils  或  yum install binutils",
    },
    provider_module="tools.binutils.main",
    provider_class="BinutilsProvider",
))
