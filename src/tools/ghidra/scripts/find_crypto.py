# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""识别加密算法特征常量。

扫描全部已初始化内存块，匹配常见加密算法的特征字节序列：
  AES S-box / 逆 S-box、MD5 K[]、SHA-1 H0、SHA-256 K[]、
  TEA/XTEA delta、CRC32 表、Blowfish S-box、RC6 P/Q 等。

同时搜索小端和大端两种字节序（4 字节常量）。
"""

from _common import emit_result, JAVA_ERRORS, warn, fail

from jarray import zeros

prog = currentProgram

# 特征库：algo / 字节序列 / 字节序说明 / 备注
SIGNATURES = [
    {"algo": "AES_SBOX", "sig": [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5],
     "note": u"AES S-box 前 8 字节"},
    {"algo": "AES_INVSBOX", "sig": [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38],
     "note": u"AES 逆 S-box 前 8 字节"},
    {"algo": "MD5_K", "sig": [0x78, 0xa4, 0x6a, 0xd7], "endian": "le",
     "note": "K[0]=0xd76aa478 (LE)"},
    {"algo": "MD5_K", "sig": [0xd7, 0x6a, 0xa4, 0x78], "endian": "be",
     "note": "K[0]=0xd76aa478 (BE)"},
    {"algo": "SHA1_H", "sig": [0x67, 0x45, 0x23, 0x01], "endian": "be",
     "note": "H0=0x67452301"},
    {"algo": "SHA256_K", "sig": [0x42, 0x8a, 0x2f, 0x98], "endian": "be",
     "note": "K[0]=0x428a2f98"},
    {"algo": "TEA_DELTA", "sig": [0xb9, 0x79, 0x37, 0x9e], "endian": "le",
     "note": u"delta=0x9e3779b9 (LE)，TEA/XTEA/RC6 共用"},
    {"algo": "TEA_DELTA", "sig": [0x9e, 0x37, 0x79, 0xb9], "endian": "be",
     "note": u"delta=0x9e3779b9 (BE)，TEA/XTEA/RC6 共用"},
    {"algo": "CRC32_TABLE", "sig": [0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77],
     "note": u"CRC32 表前两项 (LE)"},
    {"algo": "BLOWFISH_S0", "sig": [0xd1, 0x31, 0x0a, 0x02], "endian": "be",
     "note": "Blowfish S0[0]=0xd1310a02"},
    {"algo": "RC6_P32", "sig": [0x63, 0x51, 0xe1, 0xb7], "endian": "le",
     "note": "P32=0xb7e15163 (LE)"},
    {"algo": "DES_SBOX", "sig": [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     "note": u"DES S1 第一行（未优化的字节表）"},
    {"algo": "SM4_SBOX", "sig": [0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7],
     "note": u"SM4 S-box 前 8 字节"},
    {"algo": "SM4_FK", "sig": [0xa3, 0xb1, 0xba, 0xc6], "endian": "be",
     "note": "SM4 FK[0]=0xa3b1bac6"},
]

mem = prog.getMemory()
matches = []
skipped = []
scanned_bytes = 0
uninitialized = []
seen_signatures = set(tuple(entry["sig"]) for entry in SIGNATURES)
for entry in list(SIGNATURES):
    if len(entry["sig"]) == 4 and entry.get("endian") in ("le", "be"):
        reversed_sig = list(reversed(entry["sig"]))
        if tuple(reversed_sig) not in seen_signatures:
            SIGNATURES.append({
                "algo": entry["algo"], "sig": reversed_sig,
                "endian": "be" if entry["endian"] == "le" else "le",
                "note": entry["algo"] + " alternate byte order",
            })
            seen_signatures.add(tuple(reversed_sig))
patterns = [(entry, "".join(chr(b) for b in entry["sig"])) for entry in SIGNATURES]
overlap = max(len(pattern) for _, pattern in patterns) - 1

for block in mem.getBlocks():
    if not block.isInitialized():
        uninitialized.append(block.getName())
        continue
    size = block.getSize()
    if size <= 0:
        continue
    offset = 0
    tail = ""
    while offset < size:
        try:
            monitor.checkCancelled()
        except JAVA_ERRORS as exc:
            fail(u"加密常量扫描被取消: %s" % exc, code="ghidra.scan_cancelled",
                 data={"matches": matches, "scanned_bytes": scanned_bytes, "complete": False},
                 limitations=[u"扫描被取消，当前 matches 仅是已扫描片段的候选，不能判断未扫描区域。"])
        read_size = min(size - offset, 1024 * 1024)
        try:
            buf = zeros(read_size, "b")
            start = block.getStart().add(offset)
            count = mem.getBytes(start, buf)
            if count <= 0:
                raise ValueError("empty memory read")
            data = tail + "".join(chr(b & 0xff) for b in buf[:count])
        except JAVA_ERRORS as exc:
            skipped.append({"block": block.getName(), "offset": offset, "error": str(exc)})
            break

        for entry, pattern in patterns:
            i = data.find(pattern)
            while i >= 0:
                # Matches fully in the overlap were reported in the last chunk.
                if i + len(pattern) <= len(tail):
                    i = data.find(pattern, i + 1)
                    continue
                matches.append({
                    "algorithm": entry["algo"],
                    "address": str(block.getStart().add(offset - len(tail) + i)),
                    "endian": entry.get("endian", "any"),
                    "note": entry.get("note", ""),
                    "matched_length": len(pattern),
                })
                i = data.find(pattern, i + 1)
        tail = data[-overlap:]
        offset += count
        scanned_bytes += count

if skipped:
    warn("ghidra.crypto_scan_incomplete", u"部分初始化内存没有扫描成功。",
         u"扫描跳过了读取失败的内存范围；无匹配不能排除这些区域存在特征常量。",
         details={"skipped_ranges": skipped})
    if scanned_bytes == 0:
        fail(u"所有待扫描内存读取失败", code="ghidra.crypto_scan_failed",
             data={"matches": matches, "skipped_ranges": skipped, "complete": False})
if scanned_bytes == 0 and not skipped:
    warn("ghidra.crypto_scan_empty", "No initialized memory bytes were scanned.",
         "No searchable initialized memory was available; absence of matches is not evidence of absence of crypto.")
if uninitialized:
    warn("ghidra.uninitialized_memory_skipped", u"未扫描未初始化内存块。",
         u"扫描只覆盖文件中可读取的初始化内存，不覆盖这些块的运行时内容。",
         details={"blocks": uninitialized})
emit_result({"matches": matches, "count": len(matches), "skipped_ranges": skipped,
             "complete": not bool(skipped), "scanned_bytes": scanned_bytes,
             "uninitialized_blocks": uninitialized})
