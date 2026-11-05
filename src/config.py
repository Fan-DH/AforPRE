"""共享配置：主体程序的配置加载与校验。

只承载与引擎无关的通用配置；各引擎的专属校验放在 src/tools/<engine>/config.py。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    workspace: str
    timeout: int          # 单次外部工具调用的超时秒数
    min_string_len: int   # strings 工具的最小长度阈值


def load_config() -> Config:
    workspace = os.environ.get("APRE_WORKSPACE") or str(Path.cwd() / "work")
    timeout = int(os.environ.get("APRE_TIMEOUT") or "30")
    min_string_len = int(os.environ.get("APRE_MIN_STRING_LEN") or "4")
    cfg = Config(
        workspace=workspace,
        timeout=timeout,
        min_string_len=min_string_len,
    )
    validate_config(cfg)
    return cfg


def validate_config(cfg: Config) -> None:
    """主体配置校验：数值范围与必填项。"""
    if cfg.timeout <= 0:
        raise ValueError(f"APRE_TIMEOUT 必须为正数，得到 {cfg.timeout}")
    if cfg.min_string_len <= 0:
        raise ValueError(f"APRE_MIN_STRING_LEN 必须为正数，得到 {cfg.min_string_len}")
    if not cfg.workspace:
        raise ValueError("APRE_WORKSPACE 不能为空")
