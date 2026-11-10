"""Purpose-specific branch, memory, value and observed-path inspection."""
import collections
import hashlib
import json

from tools.base import ProviderError
from tools.track.analysis import origin_view
from tools.track.store import payload
from tools.track.evidence import FLAGS, branch_kind, flag_writer, indirect_transfer, location, matches_source, mnemonic, operand, page, scan


def branches(db, args):
    events, work = scan(db, args, kind="control")
    items = []
    for row, event, ins in events:
        kind = branch_kind(ins)
        indirect = indirect_transfer(ins)
        requested = args.get("branch_kind", "any")
        if requested != "any" and not (requested == "indirect" and indirect) and requested != kind:
            continue
        reads = [(n, s, o) for n, (s, o) in enumerate(zip(ins["operands"], event["operands"])) if s["read"]]
        condition, target = [], []
        for _, spec, op in reads:
            if spec["name"].lower() in FLAGS or (kind == "conditional" and mnemonic(ins).startswith(("loop", "jrcxz", "jecxz", "jcxz"))):
                condition += op["before"]
            elif spec["name"].lower() not in {"rsp", "esp", "sp"}:
                target += op["before"]
        address = [o.get("address_tag", 0) for o in event["operands"]]
        if args.get("tainted_only", True) and not any(condition + target + address):
            continue
        items.append({"line": row["line"], "seq": event["seq"], "tid": event["tid"], "kind": kind,
                      "location": location(ins), "indirect": indirect, "taken": event["taken"], "recorded_target": hex(event["target"]),
                      "condition_origins": origin_view(db, condition, 16), "target_data_origins": origin_view(db, target, 16),
                      "address_origins": origin_view(db, address, 16),
                      "operands": [operand(db, s, o, n) for n, s, o in reads],
                      "flag_writer": flag_writer(db, event, row["line"], args.get("lookback", 100)),
                      "next_call": {"tool": "track_explain", "arguments": {"trace_id": args["trace_id"], "seq": event["seq"]}}})
        if len(items) > args.get("limit", 20):
            break
    result = page(items, work, args)
    result["scope"] = "分支种类按已有反汇编分类；标志位整体近似，candidate 不是精确条件表达式或约束。target 为采集器记录值，taken 单独解释。"
    return result


def memory(db, args):
    # event_filter validates the same address interval and narrows relevant events in SQL.
    events, work = scan(db, args)
    begin = int(args["address"], 16)
    end = begin + args.get("address_length", 1)
    items = []
    for row, event, ins in events:
        accesses = []
        for n, (spec, op) in enumerate(zip(ins["operands"], event["operands"])):
            if "address" not in op or not (op["address"] < end and op["address"] + spec["width"] > begin):
                continue
            mode = args.get("access", "any")
            if mode != "any" and not spec[mode]:
                continue
            low, high = max(begin - op["address"], 0), min(end - op["address"], spec["width"])
            # A selected range must match these particular bytes, not another operand in the event.
            tags = (op["before"][low:high] if spec["read"] else []) + op.get("after", [])[low:high] + [op.get("address_tag", 0)]
            if not matches_source(db, tags, work["source_selection"]):
                continue
            changes = [i for i in range(low, high) if "after" in op and op["after"][i] != op["before"][i]]
            if args.get("changes_only") and not changes:
                continue
            access = operand(db, spec, op, n)
            access.update(overlap_address=hex(op["address"] + low), overlap_length=high - low,
                          overlap_changed_bytes=changes, overlap_before_origins=origin_view(db, op["before"][low:high], 16),
                          overlap_after_origins=origin_view(db, op.get("after", [])[low:high], 16))
            accesses.append(access)
        if accesses:
            items.append({"line": row["line"], "seq": event["seq"], "tid": event["tid"], "location": location(ins), "accesses": accesses})
        if len(items) > args.get("limit", 20):
            break
    result = page(items, work, args)
    result["scope"] = "仅已记录的指令访存；after 是预计标签。内核写入、未记录清除和未知指令可能缺失，不重建任意时刻完整内存；seq 不证明线程间 happens-before。"
    return result


def values(db, args):
    definition = payload(db, "instructions", args["instruction_id"])
    if definition is None:
        raise ProviderError("instruction_id 不存在", status="not_found")
    if "operand" in args and args["operand"] >= len(definition["operands"]):
        raise ProviderError("operand 超出指令操作数范围")
    events, work = scan(db, args)
    items = []
    for row, event, ins in events:
        if "operand" in args and args["operand"] >= len(ins["operands"]):
            raise ProviderError("operand 超出指令操作数范围")
        ops = [operand(db, spec, op, n) for n, (spec, op) in enumerate(zip(ins["operands"], event["operands"]))
               if "operand" not in args or n == args["operand"]]
        items.append({"line": row["line"], "seq": event["seq"], "tid": event["tid"], "location": location(ins),
                      "policy": event["policy"], "operands": ops})
        if len(items) > args.get("limit", 20):
            break
    result = page(items, work, args)
    result["scope"] = "执行前值的有序实例；缺值不补零，不从 after 标签推算执行后数值。来源集合截断可通过 track_query tags 展开。"
    return result


def path(db, args):
    events, work = scan(db, args, kind="control")
    items, repeats = [], collections.defaultdict(list)
    identities = []
    for row, event, ins in events:
        kind = branch_kind(ins)
        item = {"line": row["line"], "seq": event["seq"], "tid": event["tid"], "location": location(ins),
                "kind": kind, "taken": event["taken"], "recorded_target": hex(event["target"])}
        items.append(item)
        identities.append([ins["image"], ins["image_offset"], event["taken"], event["target"]])
        if kind in ("conditional", "direct", "indirect") and event["taken"] and event["target"] <= ins["ip"]:
            repeats[(ins["id"], event["target"])].append(item)
    candidates = []
    for (iid, target), group in repeats.items():
        if len(group) >= 2:
            candidates.append({"instruction_id": iid, "recorded_target": hex(target), "observed_transfers": len(group),
                               "first_seq": group[0]["seq"], "last_seq": group[-1]["seq"],
                               "evidence_seqs": [g["seq"] for g in group[:8]], "iterations_verified": False})
    candidates.sort(key=lambda c: (-c["observed_transfers"], c["first_seq"]))
    result = page(items, work, args)
    result.update(window_fingerprint=hashlib.sha256(json.dumps(identities).encode()).hexdigest(),
                  loop_candidates=candidates[:20], loop_candidates_truncated=len(candidates) > 20,
                  scope="同线程已记录/已筛选控制转移顺序；指纹仅用于本轨迹窗口。候选来自扫描窗口内重复后向转移，可能是重试或重复调用；无完整路径、CFG、嵌套循环或迭代次数保证。")
    return result
