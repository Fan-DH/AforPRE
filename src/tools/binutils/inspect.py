"""inspect_target 操作：解析 ELF 概览。"""

from __future__ import annotations

import re

from contracts.results import UNSUPPORTED_FORMAT
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
    lines = objdump_h.splitlines()
    for index, line in enumerate(lines):
        parts = line.split()
        # 形如: ['12', '.rodata', '00000013', '0000000000002000',
        #        '0000000000002000', '00002000', '2**2']
        if len(parts) < 7 or not parts[0].isdigit():
            continue
        try:
            flags = lines[index + 1] if index + 1 < len(lines) else ""
            sections.append({
                "name": parts[1],
                "size": int(parts[2], 16),
                "vma": int(parts[3], 16),
                "file_offset": int(parts[5], 16),
                "allocated": "ALLOC" in flags,
                "executable": "CODE" in flags,
                "has_contents": "CONTENTS" in flags,
            })
        except (ValueError, IndexError):
            continue
    return sections


def inspect_target(provider, args: dict) -> dict:
    path = provider.target_path(args)
    with open(path, "rb") as fh:
        if fh.read(4) != b"\x7fELF":
            raise ProviderError(f"目标不是 ELF 文件: {path}", UNSUPPORTED_FORMAT)
    header = provider._run(["readelf", "-h", path])

    sections_text = provider._run(["objdump", "-h", path])
    info = parse_header(header)
    info.update(
        path=path,
        is_elf=True,
        sections=parse_sections(sections_text),
    )
    return info
