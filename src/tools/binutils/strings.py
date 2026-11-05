"""search_strings 操作：提取并筛选静态字符串。"""

from __future__ import annotations

import re


def search_strings(provider, args: dict) -> dict:
    path = provider.target_path(args)
    pattern = args.get("pattern")
    min_length = args.get("min_length", provider.config.min_string_len)
    rx = re.compile(pattern, re.IGNORECASE) if pattern else None

    raw = provider._run(["strings", "-a", "-t", "x", "-n", str(min_length), path])

    all_strings = []
    for line in raw.splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]+)\s+(.*)$", line)
        if not m:
            continue
        all_strings.append({
            "file_offset": int(m.group(1), 16),
            "text": m.group(2),
        })

    matched = all_strings
    if rx is not None:
        matched = [s for s in all_strings if rx.search(s["text"])]

    return {"total": len(all_strings), "matched": matched, "count": len(matched)}
