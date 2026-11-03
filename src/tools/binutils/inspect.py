"""inspect_target 操作：解析 ELF 概览。"""

from __future__ import annotations

import os
import re

from tools.base import ProviderError


def parse_header(header: str) -> dict:
    def grab(label: str) -> str:
        m = re.search(rf"^\s*{re.escape(label)}:\s*(.+)$", header, re.MULTILINE)
        return m.group(1).strip() if m else ""

    return {
        "class": grab("Class"),
        "machine": grab("Machine"),
        "type": grab("Type"),
        "entry_point": grab("Entry point address"),
    }


def parse_sections(objdump_h: str) -> list[dict]:
    """从 objdump -h 输出解析节表：name / size / vma / file_offset。"""
    sections = []
    for line in objdump_h.splitlines():
        parts = line.split()
        # 形如: ['12', '.rodata', '00000013', '0000000000002000',
        #        '0000000000002000', '00002000', '2**2']
        if len(parts) < 7 or not parts[0].isdigit():
            continue
        try:
            sections.append({
                "name": parts[1],
                "size": int(parts[2], 16),
                "vma": int(parts[3], 16),
                "file_offset": int(parts[5], 16),
            })
        except (ValueError, IndexError):
            continue
    return sections


def inspect_target(provider, args: dict) -> dict:
    target_path = args["target_path"]
    path = os.path.abspath(target_path)
    if not os.path.isfile(path):
        raise ProviderError(f"目标不存在或不是文件: {target_path}")

    try:
        header = provider._run(["readelf", "-h", path])
    except ProviderError as exc:
        return {"path": path, "is_elf": False,
                "error": f"readelf 无法解析，可能不是 ELF 文件: {exc}"}

    sections_text = provider._run(["objdump", "-h", path])
    info = parse_header(header)
    info.update(
        path=path,
        is_elf=True,
        sections=parse_sections(sections_text),
    )
    return info