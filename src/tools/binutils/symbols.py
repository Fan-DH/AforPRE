"""list_symbols 操作：列出已定义符号。"""

from __future__ import annotations

import os
import re


def list_symbols(provider, args: dict) -> dict:
    path = os.path.abspath(args["target_path"])
    raw = provider._run(["nm", "-n", "--defined-only", path])

    symbols = []
    for line in raw.splitlines():
        parts = line.split()
        # 形如: "0000000000001139 T main"
        if len(parts) >= 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
            symbols.append({
                "address": parts[0],
                "type": parts[1],
                "name": parts[-1],
            })
    return {"symbols": symbols, "count": len(symbols)}