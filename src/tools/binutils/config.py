"""binutils 引擎的专属环境校验。

共享配置在 src/config/；这里只校验本引擎依赖的系统二进制是否齐全。
"""

from __future__ import annotations

import shutil

REQUIRED_BINARIES = ("readelf", "strings", "nm", "objdump")


def missing_binaries() -> list[str]:
    """返回系统里缺失的 binutils 工具名。"""
    return [name for name in REQUIRED_BINARIES if shutil.which(name) is None]


def require_binutils() -> None:
    """校验依赖齐全，否则抛出 RuntimeError。"""
    missing = missing_binaries()
    if missing:
        raise RuntimeError("缺少 binutils 工具: " + ", ".join(missing))