"""Shared bounded reads for advanced analysis; no changes to the native trace format."""
import json
import re

from tools.base import ProviderError
from tools.track.analysis import bounded_page, event_filter, origin_view
from tools.track.store import payload

WORK_BYTES = 16 * 1024 * 1024
FLAGS = {"rflags", "eflags", "gflags", "flags"}


def mnemonic(definition):
    parts = definition["asm"].lower().split()
    while parts and parts[0] in {"rep", "repe", "repne", "lock", "bnd", "notrack"}:
        parts.pop(0)
    return parts[0] if parts else ""


def location(definition):
    return {"instruction_id": definition["id"], "image": definition["image"][:4096],
            "image_offset": hex(definition["image_offset"]), "runtime_address": hex(definition["ip"]),
            "routine": definition["routine"][:1024], "asm": definition["asm"][:512],
            "routine_source": definition.get("routine_source", "legacy_unverified"),
            "routine_verified": False,
            "metadata_truncated": len(definition["image"]) > 4096 or len(definition["routine"]) > 1024,
            "asm_truncated": len(definition["asm"]) > 512}


def scan(db, args, *, kind=None):
    where, params, selected = event_filter(db, args)
    where += " AND r.line>?"
    params.append(args.get("cursor", 0))
    if kind:
        where += " AND r.kind=?"
        params.append(kind)
    else:
        where += " AND r.kind IN ('step','control')"
    maximum = args.get("scan_limit", 2000)
    rows = db.execute("SELECT r.*,i.payload definition FROM records r JOIN instructions i ON i.id=r.ins WHERE " + where +
                      " ORDER BY r.line LIMIT ?", [*params, maximum + 1])
    events, cache, used, more = [], {}, 0, False
    for row in rows:
        size = len(row["payload"]) + (len(row["definition"]) if row["ins"] not in cache else 0)
        if len(events) >= maximum or used + size > WORK_BYTES:
            if not events:
                raise ProviderError("单条记录超出 16 MiB 分析工作集；请导出原始轨迹查看。")
            more = True
            break
        used += size
        if row["ins"] not in cache:
            cache[row["ins"]] = json.loads(row["definition"])
        events.append((dict(row), json.loads(row["payload"]), cache[row["ins"]]))
    return events, {"events_scanned": len(events), "work_bytes": used, "scan_truncated": more,
                    "scan_limit": maximum, "next_scan_cursor": events[-1][0]["line"] if more else None,
                    "first_line": events[0][0]["line"] if events else None,
                    "last_line": events[-1][0]["line"] if events else None,
                    "source_selection": selected}


def page(items, work, args):
    result = bounded_page(items, args.get("limit", 20))
    limited = result["truncated"]
    result["truncated"] = limited or work["scan_truncated"]
    result["next_cursor"] = (result["items"][-1]["line"] if limited and result["items"]
                             else work["next_scan_cursor"])
    result["analysis_window"] = work
    return result


def matches_source(db, tags, selection):
    tags = sorted(set(tags) - {0})
    if not selection:
        return True
    if not tags:
        return False
    marks = ",".join("?" for _ in tags)
    return db.execute(f"SELECT 1 FROM origins WHERE tag IN ({marks}) AND input_id=? AND offset>=? AND offset<? LIMIT 1",
                      [*tags, selection["input_id"], selection["offset"], selection["offset"] + selection["length"]]).fetchone() is not None


def operand(db, spec, op, index, *, origin_limit=8):
    result = {"index": index, "name": spec["name"], "width": spec["width"], "read": spec["read"], "write": spec["write"],
              "before_origins": origin_view(db, op["before"], origin_limit),
              "value_available": "value_before" in op, "before_is_data_input": spec["read"]}
    if "value_before" in op:
        result["value_before"] = op["value_before"]
        result["value_complete"] = len(op["value_before"]) == spec["width"] * 2
        if result["value_complete"] and spec["width"] <= 8:
            b = bytes.fromhex(op["value_before"])
            result["unsigned_before"] = str(int.from_bytes(b, "little"))
            result["signed_before"] = str(int.from_bytes(b, "little", signed=True))
    if "after" in op:
        result["after_origins"] = origin_view(db, op["after"], origin_limit)
        result["tag_changes"] = [{"byte": i, "before_tag": a, "after_tag": b} for i, (a, b) in enumerate(zip(op["before"], op["after"])) if a != b]
    if "address" in op:
        result.update(address=hex(op["address"]), address_origins=origin_view(db, [op["address_tag"]], origin_limit))
        for component in ("base", "index", "load_address"):
            if component + "_tag" in op:
                result[component + "_origins"] = origin_view(db, [op[component + "_tag"]], origin_limit)
    return result


def flag_writer(db, event, line, lookback):
    current = []
    definition = payload(db, "instructions", event["ins"])
    for spec, op in zip(definition["operands"], event["operands"]):
        if spec["read"] and spec["name"].lower() in FLAGS:
            current += op["before"]
    if not current:
        return {"status": "no_flags_operand", "candidate": None}
    barrier = db.execute("SELECT MAX(line) FROM records WHERE kind='gap' AND line<?", (line,)).fetchone()[0] or 0
    rows = db.execute("SELECT * FROM records WHERE tid=? AND seq<? AND line>? AND kind IN ('step','control') ORDER BY seq DESC LIMIT ?",
                      (event["tid"], event["seq"], barrier, lookback))
    for row in rows:
        ins = payload(db, "instructions", row["ins"])
        raw = json.loads(row["payload"])
        for spec, op in zip(ins["operands"], raw["operands"]):
            if spec["write"] and spec["name"].lower() in FLAGS:
                compatible = op.get("after") == current
                candidate = {"seq": raw["seq"], "line": row["line"], "location": location(ins),
                             "policy": raw["policy"], "tags_match": compatible,
                             "operands": [operand(db, s, o, n) for n, (s, o) in enumerate(zip(ins["operands"], raw["operands"])) if s["read"]]}
                return {"status": "matching_logged_writer" if compatible else "tag_mismatch", "candidate": candidate,
                        "exact_dependency_proven": False}
    return {"status": "not_found_within_window", "candidate": None, "gap_barrier_line": barrier or None}


def branch_kind(ins):
    m = mnemonic(ins)
    if m.startswith("ret"):
        return "return"
    if m.startswith("call"):
        return "call"
    if (m.startswith("j") and m not in {"jmp", "jmpq"}) or m.startswith("loop"):
        return "conditional"
    if m in {"jmp", "jmpq"} and not re.search(r"\bjmpq?\s+(?:0x)?[0-9a-f]+\s*$", ins["asm"].lower()):
        return "indirect"
    return "direct"


def indirect_transfer(ins):
    kind = branch_kind(ins)
    return kind in ("return", "indirect") or (kind == "call" and not re.search(r"\bcallq?\s+(?:0x)?[0-9a-f]+\s*$", ins["asm"].lower()))
