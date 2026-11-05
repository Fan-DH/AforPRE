"""get_xrefs / disassemble 操作：反汇编与字符串引用定位。"""

from __future__ import annotations

import re

from tools.binutils.inspect import parse_sections


def disassemble(provider, args: dict) -> dict:
    path = provider.target_path(args)
    return {"disassembly": provider._run(["objdump", "-d", path])}


def _file_offset_to_vma(file_offset: int, sections: list[dict]) -> int | None:
    for sec in sections:
        if sec["size"] == 0 or not sec.get("allocated", True) or not sec.get("has_contents", True):
            continue
        if sec["file_offset"] <= file_offset < sec["file_offset"] + sec["size"]:
            return sec["vma"] + (file_offset - sec["file_offset"])
    return None


def get_xrefs(provider, args: dict) -> dict:
    """Direct operands plus one-hop, aligned absolute data-pointer candidates."""
    from pathlib import Path
    needle = args['needle']
    path = provider.target_path(args)
    raw = Path(path).read_bytes()
    encoded = needle.encode('utf-8')
    if not encoded:
        raise ValueError('needle cannot be empty')
    if raw[:4] != b'\x7fELF' or len(raw) < 16 or raw[4] not in (1, 2) or raw[5] not in (1, 2):
        raise ValueError('get_xrefs requires an ELF with known pointer width and byte order')
    width, byteorder = (4 if raw[4] == 1 else 8), ('little' if raw[5] == 1 else 'big')
    sections = parse_sections(provider._run(['objdump', '-h', path]))
    lines = provider._run(['objdump', '-d', path]).splitlines()
    limit = args.get('max_results', 1000)
    xrefs, seen, total = [], set(), 0
    def append(item):
        nonlocal total
        key = (item['kind'], item['from_address'], item['vma'], item.get('via'))
        if key in seen:
            return
        seen.add(key)
        total += 1
        if len(xrefs) < limit:
            xrefs.append(item)
    def references(address):
        hexv = '%x' % address
        pattern = re.compile(r'(?:#\s*|\b0x)0*' + hexv + r'\b|\s0*' + hexv + r'\s*<')
        for line in lines:
            source = re.match(r'^\s*([0-9a-fA-F]+):', line)
            if source and pattern.search(line.split(':', 1)[1]):
                yield '0x%x' % int(source.group(1), 16), line.strip()
    mapped = []
    offset = raw.find(encoded)
    while offset >= 0:
        vma = _file_offset_to_vma(offset, sections)
        if vma is not None:
            mapped.append((offset, vma))
        offset = raw.find(encoded, offset + 1)
    for offset, vma in mapped:
        base = {'file_offset': offset, 'vma': '0x%x' % vma}
        for source, line in references(vma):
            append({**base, 'kind': 'code_direct', 'from_address': source, 'line': line})
        pointer = vma.to_bytes(width, byteorder)
        for section in sections:
            if not section['allocated'] or not section['has_contents'] or section.get('executable'):
                continue
            contents = raw[section['file_offset']:section['file_offset'] + section['size']]
            position = contents.find(pointer)
            while position >= 0:
                source = section['vma'] + position
                if source % width == 0:
                    source_text = '0x%x' % source
                    append({**base, 'kind': 'data_pointer_candidate', 'from_address': source_text,
                            'section': section['name'], 'pointer_size': width,
                            'evidence': 'aligned_absolute_pointer_bytes'})
                    for code, line in references(source):
                        append({**base, 'kind': 'code_via_pointer', 'from_address': code,
                                'via': source_text, 'line': line})
                position = contents.find(pointer, position + 1)
    return {'needle': needle, 'xrefs': xrefs, 'count': len(xrefs), 'total_matches': total,
            'truncated': total > len(xrefs), 'string_locations': len(mapped),
            'coverage': {'code': 'objdump_text_operands', 'data': 'aligned_absolute_pointers',
                         'indirection_depth': 1, 'runtime_references': False},
            'limitations': ['静态启发式查询：数据指针命中是字节候选，不证明运行时使用。',
                '未解析重定位语义、相对/编码/未对齐指针、多级指针和运行时构造；count=0 不证明没有引用。'] +
                (['达到 max_results，返回结果已截断。'] if total > len(xrefs) else [])}
