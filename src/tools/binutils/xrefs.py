"""get_xrefs / disassemble 操作：反汇编与字符串引用定位。"""

from __future__ import annotations

import os
import re

from tools.binutils.inspect import parse_sections


def disassemble(provider, args: dict) -> dict:
    path = os.path.abspath(args["target_path"])
    return {"disassembly": provider._run(["objdump", "-d", path])}


def _file_offset_to_vma(file_offset: int, sections: list[dict]) -> int | None:
    for sec in sections:
        if sec["size"] == 0:
            continue
        if sec["file_offset"] <= file_offset < sec["file_offset"] + sec["size"]:
            return sec["vma"] + (file_offset - sec["file_offset"])
    return None


def get_xrefs(provider, args: dict) -> dict:
    """在反汇编中查找对某个字符串内容的引用。

    思路：定位字符串的文件偏移 → 换算成虚拟地址（VMA）→ 在 objdump -d
    的注释（形如 `# 2000 <sym>`）中搜索该地址。
    """
    target_path = args["target_path"]
    needle = args["needle"]
    path = os.path.abspath(target_path)

    raw_strings = provider._run(["strings", "-a", "-t", "x", path])
    file_offsets = []
    for line in raw_strings.splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]+)\s+(.*)$", line)
        if m and needle in m.group(2):
            file_offsets.append(int(m.group(1), 16))

    if not file_offsets:
        return {"needle": needle, "xrefs": [],
                "note": "未在字符串表中定位到该内容，无法换算地址"}

    sections = parse_sections(provider._run(["objdump", "-h", path]))
    disasm = provider._run(["objdump", "-d", path])

    xrefs = []
    for off in file_offsets:
        vma = _file_offset_to_vma(off, sections)
        if vma is None:
            continue
        hexv = f"{vma:x}"
        pat = re.compile(rf"#\s*{re.escape(hexv)}\b")
        for line in disasm.splitlines():
            if pat.search(line):
                xrefs.append({
                    "file_offset": off,
                    "vma": f"0x{hexv}",
                    "line": line.strip(),
                })
    return {"needle": needle, "xrefs": xrefs, "count": len(xrefs)}