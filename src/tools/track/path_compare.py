"""Bounded sequence alignment and concrete-before-value comparison."""
import difflib
import re

from tools.track.analysis import bounded_page
from tools.track.evidence import location, scan
from tools.track.store import quality


def compare_paths(left, right, args, left_meta, right_meta):
    def collect(db, side):
        options = {"tid": args[side + "_tid"], "scan_limit": args.get("max_events", 500)}
        for key in ("seq_start", "seq_end"):
            if side + "_" + key in args:
                options[key] = args[side + "_" + key]
        for key in ("image", "routine"):
            if key in args:
                options[key] = args[key]
        return scan(db, options, kind="control" if args.get("mode", "control") == "control" else None)
    a, aw = collect(left, "left")
    b, bw = collect(right, "right")

    def keys(events):
        result = []
        for _, event, ins in events:
            text = ins["asm"]
            if event["type"] == "control":
                text = re.sub(r"\b0x[0-9a-fA-F]+\b", "<target>", text)
            result.append((ins["image"], ins["image_offset"], text, event["type"]))
        return result

    def targets(events):
        spans = {}
        for _, _, ins in events:
            key = ins["image"], ins["ip"] - ins["image_offset"]
            spans[key] = max(spans.get(key, 0), ins["ip"] + 1)

        def resolve(address):
            candidates = [(name, address - base) for (name, base), high in spans.items() if base <= address < high]
            return candidates[0] if len(candidates) == 1 else None
        return resolve

    atarget, btarget = targets(a), targets(b)
    changes, unknown_values, unknown_targets = [], 0, 0
    matcher = difflib.SequenceMatcher(None, keys(a), keys(b), autojunk=False)
    def anchor(item):
        row, event, ins = item
        return {"seq": event["seq"], "line": row["line"], "location": location(ins)}
    for operation, i, j, k, l in matcher.get_opcodes():
        if operation != "equal":
            changes.append({"kind": operation, "left_position": i, "right_position": k,
                            "control_changed": any(e[1]["type"] == "control" for e in a[i:j] + b[k:l]),
                            "left_count": j - i, "right_count": l - k,
                            "left": [anchor(x) for x in a[i:min(j, i + 4)]], "right": [anchor(x) for x in b[k:min(l, k + 4)]],
                            "samples_truncated": j - i > 4 or l - k > 4})
            continue
        for x, y in zip(range(i, j), range(k, l)):
            _, le, li = a[x]
            _, revent, ri = b[y]
            entry = {"kind": "aligned_change", "left_position": x, "right_position": y, "left": anchor(a[x]), "right": anchor(b[y])}
            changed = False
            control_changed = False
            if le["type"] == "control":
                lt, rt = atarget(le["target"]), btarget(revent["target"])
                entry["branch"] = {"left_taken": le["taken"], "right_taken": revent["taken"],
                                   "left_target": hex(le["target"]), "right_target": hex(revent["target"]),
                                   "target_comparison_available": lt is not None and rt is not None,
                                   "target_basis": "observed_module_spans"}
                changed = le["taken"] != revent["taken"] or (lt is not None and rt is not None and lt != rt)
                control_changed = changed
                unknown_targets += lt is None or rt is None
            differences = []
            for n, (ls, rs, lo, ro) in enumerate(zip(li["operands"], ri["operands"], le["operands"], revent["operands"])):
                if not any(lo["before"]) and not any(ro["before"]):
                    continue
                # Only compare compatible, complete concrete values; absent bytes are never zeros.
                if ls["name"] != rs["name"] or ls["width"] != rs["width"]:
                    unknown_values += 1
                    continue
                lv, rv = lo.get("value_before"), ro.get("value_before")
                if lv is None or rv is None or len(lv) != ls["width"] * 2 or len(rv) != rs["width"] * 2:
                    unknown_values += 1
                    continue
                if lv != rv:
                    differences.append({"operand": n, "name": ls["name"], "left_before": lv, "right_before": rv})
            if differences:
                entry["value_changes"] = differences
                changed = True
            if changed:
                entry["control_changed"] = control_changed
                entry["change_scope"] = "control_and_values" if control_changed and differences else "control" if control_changed else "values_only"
                changes.append(entry)
    cursor, limit = args.get("cursor", 0), args.get("limit", 20)
    result = bounded_page(changes[cursor:cursor + limit + 1], limit, cursor)
    identities = bool(left_meta.get("target_sha256") and left_meta.get("target_sha256") == right_meta.get("target_sha256")
                      and left_meta.get("target_unchanged") and right_meta.get("target_unchanged"))
    result.update(total_changes=len(changes), first_observed_difference=changes[0] if changes else None,
                  first_observed_control_difference=next((c for c in changes if c["control_changed"]), None),
                  value_only_changes=sum(c.get("change_scope") == "values_only" for c in changes),
                  left_window=aw, right_window=bw, left_quality=quality(left), right_quality=quality(right),
                  main_target_file_identity_matches=identities, uncomparable_value_pairs=unknown_values,
                  unresolved_target_pairs=unknown_targets,
                  scope="按显式线程和所选窗口对齐已记录事件；重复序列可能有多个合理对齐。比较带标签操作数的完整执行前值，不比较标签 ID；地址值变化可能仅来自 ASLR。共享库身份、完整路径与因果关系未证明。")
    return result
