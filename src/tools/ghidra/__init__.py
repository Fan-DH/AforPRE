"""Ghidra 引擎：用 Ghidra analyzeHeadless 进行深度反编译与分析。

推荐版本：Ghidra 11.2.1 + JDK 21（见 config.py）。
未安装时 is_available() 返回 False，上层可优雅降级到 binutils。
"""

from .main import GhidraProvider
from .config import (
    find_analyze_headless,
    is_available,
    RECOMMENDED_VERSION,
    RECOMMENDED_JDK,
)

__all__ = [
    "GhidraProvider",
    "find_analyze_headless",
    "is_available",
    "RECOMMENDED_VERSION",
    "RECOMMENDED_JDK",
]
