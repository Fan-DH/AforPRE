"""binutils 引擎的 Provider 主管。

对外暴露统一操作接口（操作名 = 工具名），内部把每个操作委托给细分模块。
生命周期：每操作启动一次 binutils 子进程，不保持常驻，也不启动 shell。
"""

from __future__ import annotations

import os
import subprocess

from config import Config
from contracts.results import NOT_FOUND, TIMEOUT
from tools.base import ProviderError
from tools.binutils import inspect, strings, symbols, xrefs


class BinutilsProvider:
    def __init__(self, config: Config):
        self.config = config

    def target_path(self, args: dict) -> str:
        path = os.path.abspath(args["target_path"])
        if not os.path.isfile(path):
            raise ProviderError(f"目标不存在或不是文件: {path}", NOT_FOUND)
        return path

    # --- 底层执行：参数化调用，避免 shell 注入 ---
    def _run(self, args: list[str]) -> str:
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace",
                env={**os.environ, "LC_ALL": "C"},
                timeout=self.config.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProviderError(f"超时: {args[0]}（>{self.config.timeout}s）", TIMEOUT) from exc
        except OSError as exc:
            raise ProviderError(f"无法启动系统工具: {args[0]}: {exc}") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise ProviderError(f"{args[0]} 退出码 {proc.returncode}: {detail}")
        return proc.stdout

    # --- 统一操作接口（操作名 = 工具名） ---
    def inspect_target(self, args: dict) -> dict:
        return inspect.inspect_target(self, args)

    def search_strings(self, args: dict) -> dict:
        return strings.search_strings(self, args)

    def list_symbols(self, args: dict) -> dict:
        return symbols.list_symbols(self, args)

    def get_xrefs(self, args: dict) -> dict:
        return xrefs.get_xrefs(self, args)

    def disassemble(self, args: dict) -> dict:
        return xrefs.disassemble(self, args)
