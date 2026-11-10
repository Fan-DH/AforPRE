"""Trace-anchored ELF coordinate mapping, with optional real Ghidra project lookup."""
from pathlib import Path
import struct

from tools.base import ProviderError
from tools.track.evidence import location
from tools.track.store import digest, payload


def elf_segments(path):
    with open(path, "rb") as f:
        file_size = Path(path).stat().st_size
        h = f.read(64)
        if len(h) != 64 or h[:6] != b"\x7fELF\x02\x01" or h[18:20] != b"\x3e\x00" or int.from_bytes(h[16:18], "little") not in (2, 3):
            raise ProviderError("模块必须为 x86-64 小端 ELF executable/shared object")
        offset = struct.unpack_from("<Q", h, 32)[0]
        size, count = struct.unpack_from("<HH", h, 54)
        if size != 56 or not 0 < count <= 4096:
            raise ProviderError("不支持的 ELF program headers")
        segments = []
        for n in range(count):
            f.seek(offset + n * size)
            raw = f.read(56)
            if len(raw) != 56:
                raise ProviderError("ELF program header 被截断")
            p = struct.unpack("<IIQQQQQQ", raw)
            if p[0] == 1:
                if p[3] + p[6] > (1 << 64) or p[5] > p[6] or p[2] + p[5] > file_size:
                    raise ProviderError("ELF 段范围溢出、被截断或 filesz 大于 memsz")
                segments.append({"start": p[3], "end": p[3] + p[6], "execute": bool(p[1] & 1)})
    if not segments:
        raise ProviderError("ELF 没有 PT_LOAD")
    return min(s["start"] & ~4095 for s in segments), segments


def map_address(provider, db, args, manifest):
    ins = payload(db, "instructions", args["instruction_id"])
    if ins is None:
        raise ProviderError("instruction_id 不存在", status="not_found")
    if args.get("use_ghidra") and "static_image_base" in args:
        raise ProviderError("use_ghidra 与 static_image_base 不能同时指定")
    if not ins["image"]:
        raise ProviderError("指令没有镜像身份，不能以它作为模块映射锚点")
    module = Path(args.get("module_path") or ins["image"]).resolve()
    if not module.is_file():
        raise ProviderError("模块文件不存在；离线分析时提供 module_path", status="not_found")
    module_hash = digest(module)
    elf_base, segments = elf_segments(module)
    runtime_base = ins["ip"] - ins["image_offset"]
    anchor = elf_base + ins["image_offset"]
    if runtime_base < 0 or not any(s["start"] <= anchor < s["end"] and s["execute"] for s in segments):
        raise ProviderError("指令偏移不落在所提供模块的可执行 PT_LOAD 中")
    identity = bool(ins["image"] == manifest.get("target_path") and manifest.get("target_unchanged")
                    and module_hash == manifest.get("target_sha256"))
    static_base, basis, ghidra = elf_base, "ELF", None
    if "static_image_base" in args:
        try:
            static_base = int(args["static_image_base"], 16)
        except ValueError as exc:
            raise ProviderError("static_image_base 必须为十六进制地址") from exc
        basis = "caller_supplied"
    if args.get("use_ghidra"):
        from tools.ghidra.runner import GhidraRunner
        ghidra = GhidraRunner(provider.config.workspace).run_script(str(module), "inspect.py", {}, read_only=True)
        if not str(ghidra.get("language", "")).startswith("x86:LE:64"):
            raise ProviderError("Ghidra 程序架构与 track 不一致")
        static_base, basis = int(ghidra["image_base"], 16), "ghidra_project"
    direction = args.get("direction", "runtime_to_static")
    if direction == "static_to_runtime" and "address" not in args:
        raise ProviderError("static_to_runtime 需要 address")
    try:
        address = int(args["address"], 16) if "address" in args else ins["ip"]
    except ValueError as exc:
        raise ProviderError("address 必须为十六进制地址") from exc
    relative = address - (runtime_base if direction == "runtime_to_static" else static_base)
    output = (static_base if direction == "runtime_to_static" else runtime_base) + relative
    elf_address = elf_base + relative
    if not all(0 <= x < (1 << 64) for x in (address, output, static_base)) or not any(s["start"] <= elf_address < s["end"] for s in segments):
        raise ProviderError("待换算地址超出该锚点模块的 PT_LOAD 范围")
    static_address = static_base + relative
    if ghidra and not any(int(b["start"], 16) <= static_address <= int(b["end"], 16) for b in ghidra["memory_blocks"]):
        raise ProviderError("换算地址不在实际 Ghidra 工程内存块中")
    if digest(module) != module_hash:
        raise ProviderError("映射过程中模块文件发生变化")
    return {"anchor": location(ins), "direction": direction, "input_address": hex(address), "output_address": hex(output),
            "module_path": str(module), "module_sha256": module_hash, "module_file_identity_verified": identity,
            "runtime_image_base": hex(runtime_base), "static_image_base": hex(static_base), "elf_image_base": hex(elf_base),
            "image_offset": hex(relative), "static_base_source": basis, "ghidra_address_verified": ghidra is not None,
            "scope": "runtime 是本次 Pin 采集的模块地址，不是另一次 GDB 运行。PT_LOAD/文件身份校验不证明无自修改/JIT；共享库与导入日志缺原始模块哈希时只能提供几何换算。"}
