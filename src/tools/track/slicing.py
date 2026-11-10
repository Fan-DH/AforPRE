"""Bounded backward evidence graph, deliberately not an exact dynamic slicer."""
import json
import re

from tools.base import ProviderError
from tools.track.evidence import FLAGS, WORK_BYTES, location, mnemonic
from tools.track.store import payload


def register(name):
    name = name.lower()
    if name in FLAGS:
        return "flags", 0, False
    for root, aliases in {
        "rax": ["rax", "eax", "ax", "al", "ah"], "rbx": ["rbx", "ebx", "bx", "bl", "bh"],
        "rcx": ["rcx", "ecx", "cx", "cl", "ch"], "rdx": ["rdx", "edx", "dx", "dl", "dh"],
        "rsi": ["rsi", "esi", "si", "sil"], "rdi": ["rdi", "edi", "di", "dil"],
        "rbp": ["rbp", "ebp", "bp", "bpl"], "rsp": ["rsp", "esp", "sp", "spl"],
    }.items():
        if name in aliases:
            return root, int(name in {"ah", "bh", "ch", "dh"}), name == aliases[1]
    match = re.fullmatch(r"r(8|9|1[0-5])([dwb]?)", name)
    if match:
        return "r" + match[1], 0, match[2] == "d"
    match = re.fullmatch(r"[xyz]mm(\d+)", name)
    if match:
        return "zmm" + match[1], 0, False
    return None


def storage(spec, op, byte, tid):
    if "address" in op:
        return ("memory", op["address"] + byte)
    reg = register(spec["name"])
    return ("register", tid, reg[0], reg[1] + byte) if reg else None


def written_tag(spec, op, ins, tid, wanted):
    if not spec["write"]:
        return None
    if wanted[0] == "memory":
        if "address" not in op:
            return None
        index = wanted[1] - op["address"]
    else:
        if "address" in op:
            return None
        reg = register(spec["name"])
        if not reg or tid != wanted[1] or reg[0] != wanted[2]:
            return None
        index = wanted[3] - reg[1]
        clear_upper = reg[2] or (reg[0].startswith("zmm") and mnemonic(ins).startswith("v"))
        if clear_upper and spec["width"] <= index < (64 if reg[0].startswith("zmm") else 8):
            return -1, 0
    if 0 <= index < spec["width"]:
        return index, op["after"][index]
    return None


def backward_slice(db, args):
    seed = db.execute("SELECT * FROM records WHERE seq=? AND kind IN ('step','control')", (args["seq"],)).fetchone()
    if seed is None:
        raise ProviderError("seq 必须指向 step/control 事件", status="not_found")
    timeline, used, truncated = [], 0, False
    maximum = args.get("scan_limit", 2000)
    cache = {}
    for row in db.execute("SELECT * FROM records WHERE line<=? AND kind IN ('input','step','control','gap','model') ORDER BY line DESC LIMIT ?", (seed["line"], maximum + 1)):
        used += len(row["payload"])
        if len(timeline) >= maximum or used > WORK_BYTES:
            truncated = True
            break
        raw = json.loads(row["payload"])
        ins = None
        if row["ins"]:
            if row["ins"] not in cache:
                cache[row["ins"]] = payload(db, "instructions", row["ins"])
                used += len(json.dumps(cache[row["ins"]]))
            ins = cache[row["ins"]]
        if used > WORK_BYTES:
            truncated = True
            break
        timeline.append((dict(row), raw, ins))
    if not timeline:
        raise ProviderError("种子事件超过分析工作集预算")
    _, raw, ins = timeline[0]
    index, start, count = args["operand"], args.get("byte_offset", 0), args.get("byte_length", 1)
    phase = args.get("phase", "before")
    if index >= len(raw["operands"]) or start + count > ins["operands"][index]["width"]:
        raise ProviderError("operand 或字节范围超出种子事件")
    if phase == "after" and "after" not in raw["operands"][index]:
        raise ProviderError("所选操作数没有 after 标签")
    nodes, edges, known, tag_sets = [], [], {}, {0: frozenset()}
    unresolved, cuts, source_pairs, response_bytes = [], set(), 0, 0
    chunks_cache = {}

    def chunks(input_id):
        nonlocal used
        if input_id not in chunks_cache:
            records = []
            for chunk in db.execute("SELECT line,payload FROM records WHERE kind='input_chunk' AND input_id=?", (input_id,)):
                used += len(chunk["payload"])
                if used > WORK_BYTES:
                    cuts.add("input_chunk_budget")
                    chunks_cache[input_id] = None
                    return None
                records.append((chunk["line"], json.loads(chunk["payload"])))
            chunks_cache[input_id] = records
        return chunks_cache[input_id]

    def origins(tag):
        nonlocal source_pairs
        if tag not in tag_sets:
            values = db.execute("SELECT input_id,offset FROM origins WHERE tag=? LIMIT 4097", (tag,)).fetchall()
            if len(values) > 4096 or source_pairs + len(values) > 65536:
                cuts.add("origin_budget")
                return None
            source_pairs += len(values)
            tag_sets[tag] = frozenset(tuple(x) for x in values)
        return tag_sets[tag]

    def add(key, data):
        nonlocal response_bytes
        if key in known:
            return known[key], False
        if len(nodes) >= args.get("max_nodes", 64):
            cuts.add("node_budget")
            return None, False
        size = len(json.dumps(data, ensure_ascii=False).encode()) + len(key) + 20
        if response_bytes + size > 70000:
            cuts.add("response_budget")
            return None, False
        response_bytes += size
        known[key] = key
        nodes.append({"id": key, **data})
        return key, True

    def edge(producer, consumer, relation, **extra):
        nonlocal response_bytes
        if producer is not None and len(edges) < 512:
            record = {"from": producer, "to": consumer, "relation": relation, **extra}
            if record not in edges:
                size = len(json.dumps(record).encode())
                if response_bytes + size > 70000:
                    cuts.add("response_budget")
                    return
                response_bytes += size
                edges.append(record)
        elif len(edges) >= 512:
            cuts.add("edge_budget")

    def stop(node, reason, **details):
        unresolved.append({"node": node, "reason": reason, **details})

    def visit(at, operand_index, state, byte, depth):
        row, event, definition = timeline[at]
        op, spec = event["operands"][operand_index], definition["operands"][operand_index]
        tag = op[state][byte]
        key = f"{event['seq']}:{operand_index}:{state}:{byte}"
        sources = origins(tag)
        node, fresh = add(key, {"seq": event["seq"], "line": row["line"], "tid": event["tid"], "operand": operand_index,
                               "phase": state, "byte": byte, "tag": tag, "location": location(definition),
                               "origins": [list(x) for x in sorted(sources or ())[:8]],
                               "origins_truncated": sources is None or len(sources) > 8})
        if not fresh:
            return node
        if not tag:
            return node
        if sources is None:
            stop(node, "origin_budget")
            return node
        if depth >= args.get("max_depth", 12):
            cuts.add("depth_budget"); stop(node, "depth_budget")
            return node
        if state == "after":
            matched = False
            for i, (s, o) in enumerate(zip(definition["operands"], event["operands"])):
                if not s["read"]:
                    continue
                for j, source_tag in enumerate(o["before"]):
                    source = origins(source_tag)
                    if source and source & sources:
                        matched = True
                        before = visit(at, i, "before", j, depth + 1)
                        edge(before, node, "same_instruction_origin_overlap_candidate")
                        if "node_budget" in cuts:
                            break
                if "node_budget" in cuts:
                    break
            if not matched:
                stop(node, "no_logged_read_with_overlapping_origin")
            return node
        wanted = storage(spec, op, byte, event["tid"])
        if wanted is None:
            stop(node, "unknown_register_alias")
            return node
        for earlier in range(at + 1, len(timeline)):
            prev_row, previous, previous_ins = timeline[earlier]
            if previous["type"] == "gap":
                stop(node, "gap_barrier", line=prev_row["line"])
                return node
            if previous["type"] == "model":
                if wanted[0] == "register" and wanted[1] == previous["tid"] and wanted[2] == "rax":
                    stop(node, "comparison_return_model", model_seq=previous["seq"],
                         return_tag=previous["return_tag"], function=previous["function"])
                    return node
                continue
            if previous["type"] == "input":
                if wanted[0] != "memory":
                    continue
                captured = chunks(previous["id"])
                if captured is None:
                    stop(node, "input_chunk_budget")
                    return node
                for chunk_line, c in captured:
                    relative = wanted[1] - c["address"]
                    if 0 <= relative < len(c["bytes"]) // 2:
                        source = (previous["id"], c["offset"] + relative)
                        if sources != frozenset([source]):
                            stop(node, "input_overwrite_tag_mismatch", input_id=previous["id"])
                            return node
                        origin, _ = add(f"input:{source[0]}:{source[1]}", {"kind": "input_byte", "input_id": source[0], "offset": source[1],
                                        "line": chunk_line, "seq": previous["seq"], "byte_hex": c["bytes"][relative * 2:relative * 2 + 2]})
                        edge(origin, node, "recorded_input_at_same_address", cross_thread=previous["tid"] != event["tid"])
                        return node
                continue
            for n, (s, o) in enumerate(zip(previous_ins["operands"], previous["operands"])):
                written = written_tag(s, o, previous_ins, previous["tid"], wanted)
                if written is None:
                    continue
                producer_byte, producer_tag = written
                if producer_tag != tag:
                    stop(node, "nearest_logged_write_tag_mismatch", writer_seq=previous["seq"], writer_tag=producer_tag)
                    return node
                producer = visit(earlier, n, "after", producer_byte, depth + 1)
                edge(producer, node, "nearest_logged_writer_same_storage_and_tag", cross_thread=previous["tid"] != event["tid"])
                return node
        stop(node, "no_writer_in_scanned_prefix")
        return node

    seeds = [visit(0, index, phase, byte, 0) for byte in range(start, start + count)]
    return {"seed_nodes": [s for s in seeds if s], "nodes": nodes, "edges": edges, "unresolved": unresolved,
            "exact_slice": False, "budget_cuts": sorted(cuts),
            "analysis_window": {"records_scanned": len(timeline), "scan_truncated": truncated, "json_work_bytes": used,
                                "first_line": timeline[-1][0]["line"], "last_line": seed["line"]},
            "scope": "最近已记录写入的候选图；指令内部连边只依据来源交集，不是逐操作数精确传递函数。未知内核写入、未记录的状态改变、故障回滚和线程交错可能破坏链条；遇可见 gap 停止。"}
