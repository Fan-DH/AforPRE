"""Bounded, evidence-first queries over immutable trace indexes."""
from __future__ import annotations

import json
import struct

from tools.base import ProviderError
from tools.track.store import payload, quality, ADDRESS_ONLY_SQL

OUTPUT_BUDGET = 48000


def hex_addresses(value):
    if isinstance(value, dict):
        return {k: hex(v) if k in ("ip", "address", "target", "image_offset") and type(v) is int
                else hex_addresses(v) for k, v in value.items()}
    if isinstance(value, list):
        return [hex_addresses(x) for x in value]
    return value


def preview(record):
    r = dict(record)
    if "origins" in r and len(r["origins"]) > 64:
        r.update(origins=r["origins"][:64], origins_count=len(r["origins"]), origins_truncated=True)
    if "bytes" in r and len(r["bytes"]) > 256:
        r.update(bytes=r["bytes"][:256], byte_length=len(r["bytes"]) // 2, bytes_truncated=True)
    return hex_addresses(r)


def source_range(db, args):
    if "input_id" not in args:
        if "offset" in args or "length" in args:
            raise ProviderError("offset/length 需要 input_id")
        return None
    row = db.execute("SELECT stored FROM inputs WHERE id=?", (args["input_id"],)).fetchone()
    if row is None:
        raise ProviderError("指定 input_id 不在已验证日志前缀中", status="not_found")
    start, length = args.get("offset", 0), args.get("length", 1)
    if start + length > row[0]:
        raise ProviderError("选择范围超出 input.stored；returned 可能包含未存储的 MSG_TRUNC 尾部。")
    captured = db.execute("SELECT COUNT(DISTINCT offset) FROM origins WHERE input_id=? AND offset>=? AND offset<?",
                          (args["input_id"], start, start + length)).fetchone()[0]
    return {"input_id": args["input_id"], "offset": start, "length": length,
            "source_bytes_recorded": captured, "fully_tagged": captured == length}


def event_filter(db, args, *, include_source=True):
    clauses, params = ["r.kind IN ('input','step','control','model','output')"], []
    for key, expression in (("tid", "r.tid=?"), ("seq_start", "r.seq>=?"), ("seq_end", "r.seq<=?"),
                            ("instruction_id", "r.ins=?"), ("event_type", "r.kind=?"),
                            ("policy", "json_extract(r.payload,'$.policy')=?")):
        if key in args:
            clauses.append(expression)
            params.append(args[key])
    if args.get("seq_start", 0) > args.get("seq_end", (1 << 63) - 1):
        raise ProviderError("seq_start 不得大于 seq_end")
    for key in ("image", "routine"):
        if key in args:
            clauses.append(f"instr(i.{key},?)>0")
            params.append(args[key])
    if "address_length" in args and "address" not in args:
        raise ProviderError("address_length 需要 address")
    if "address" in args:
        try:
            address = int(args["address"], 16)
        except ValueError as exc:
            raise ProviderError("address 必须为十六进制地址") from exc
        # SQLite cannot represent unsigned addresses above INT64_MAX exactly.
        if not 0 <= address < (1 << 63) or address + args.get("address_length", 1) >= (1 << 63):
            raise ProviderError("访存范围筛选仅支持 Linux 用户空间有符号 64 位地址；原始查询仍保留完整地址。")
        clauses.append("EXISTS (SELECT 1 FROM json_each(r.payload,'$.operands') op "
                       "JOIN json_each(i.payload,'$.operands') spec ON spec.key=op.key "
                       "WHERE json_extract(op.value,'$.address')<? AND "
                       "json_extract(op.value,'$.address')+json_extract(spec.value,'$.width')>?)")
        params.extend([address + args.get("address_length", 1), address])
    selected = source_range(db, args) if include_source else None
    if selected:
        clause = "EXISTS (SELECT 1 FROM uses u JOIN origins o ON o.tag=u.tag WHERE u.line=r.line AND o.input_id=? AND o.offset>=? AND o.offset<?"
        params.extend([selected["input_id"], selected["offset"], selected["offset"] + selected["length"]])
        if args.get("role", "any") != "any":
            clause += " AND u.role=?"
            params.append(args["role"])
        clauses.append(clause + ")")
    elif include_source and args.get("role", "any") != "any":
        clauses.append("EXISTS (SELECT 1 FROM uses u WHERE u.line=r.line AND u.role=?)")
        params.append(args["role"])
    return " AND ".join(clauses), params, selected


def evidence(db, row, expand=True):
    r = json.loads(row["payload"])
    result = {"line": row["line"], **preview(r)}
    if expand and r.get("ins"):
        result["instruction"] = preview(payload(db, "instructions", r["ins"]))
    return result


def bounded_page(items, limit, cursor=0):
    out, used = [], 0
    for item in items:
        size = len(json.dumps(item, ensure_ascii=False).encode())
        if not out and size > OUTPUT_BUDGET:
            # Always advance, even for a valid-but-huge imported metadata record.
            out.append({**{k: v for k, v in item.items() if k in ("line", "seq", "type", "id", "ins", "tag_id")},
                        "item_omitted_due_to_size": True, "item_bytes": size,
                        "note": "单条证据超过响应预算；用 track_explain 指定 operand，或 track_export(format=raw) 获取完整原始内容。"})
            break
        if len(out) >= limit or used + size > OUTPUT_BUDGET:
            break
        out.append(item)
        used += size
    return {"items": out, "returned": len(out), "truncated": len(out) < len(items),
            "next_cursor": cursor + len(out) if len(out) < len(items) else None}


def query(db, args):
    kind = args["kind"]
    cursor, limit = args.get("cursor", 0), args.get("limit", 20)
    allowed = {"trace_id", "kind", "cursor", "limit"}
    if kind == "outputs":
        unsupported = set(args) & {"image", "routine", "instruction_id", "policy", "event_type", "address", "address_length"}
        if unsupported:
            raise ProviderError("outputs 不支持指令/访存过滤器: " + ", ".join(sorted(unsupported)))
        args = {**args, "event_type": "output"}
    if kind in ("events", "flow", "outputs"):
        if "tag_id" in args or "diagnostic_type" in args:
            raise ProviderError("tag_id/diagnostic_type 只适用于 tags/diagnostics")
        where, params, selected = event_filter(db, args)
        if kind == "flow":
            where += " AND r.kind='control'"
            rows = db.execute("SELECT r.ins,r.tid,r.target,"
                              "json_extract(r.payload,'$.taken') taken,COUNT(*) count,MIN(r.seq) first_seq,MAX(r.seq) last_seq "
                              "FROM records r LEFT JOIN instructions i ON i.id=r.ins WHERE " + where +
                              " GROUP BY r.ins,r.tid,target,taken ORDER BY count DESC,r.ins,r.tid,target,taken LIMIT ? OFFSET ?",
                              [*params, limit + 1, cursor]).fetchall()
            items = [{**dict(r), "taken": bool(r["taken"]),
                      "instruction": preview(payload(db, "instructions", r["ins"]))} for r in rows]
            result = bounded_page(items, limit, cursor)
            result["coverage"] = "已记录控制转移；无完整路径/调用栈或循环语义保证。"
        else:
            rows = db.execute("SELECT r.* FROM records r LEFT JOIN instructions i ON i.id=r.ins WHERE " + where +
                              " AND r.line>? ORDER BY r.line LIMIT ?", [*params, cursor, limit + 1]).fetchall()
            items = [evidence(db, r) for r in rows]
            if kind == "outputs":
                for item in items:
                    runs = []
                    for offset, tag in enumerate(item["tags"]):
                        if runs and runs[-1]["tag"] == tag:
                            runs[-1]["length"] += 1
                        else:
                            runs.append({"offset": item["offset"] + offset, "length": 1, "tag": tag})
                    for run in runs:
                        run["sources"] = origin_view(db, [run["tag"]], 8)
                    item["source_runs"] = runs
            result = bounded_page(items, limit)
            result["next_cursor"] = result["items"][-1]["line"] if result["truncated"] and result["items"] else None
        if selected:
            result["source_selection"] = selected
        return result
    if kind == "inputs":
        allowed |= {"input_id", "offset", "length", "tid"}
    elif kind == "instructions":
        allowed |= {"instruction_id", "image", "routine"}
    elif kind == "tags":
        allowed |= {"input_id", "offset", "length", "tag_id"}
    elif kind == "diagnostics":
        allowed |= {"diagnostic_type"}
    extra = set(args) - allowed
    if extra:
        raise ProviderError(f"{kind} 不支持这些过滤器: {', '.join(sorted(extra))}")
    if kind == "tags" and "tag_id" in args:
        if not db.execute("SELECT 1 FROM tags WHERE id=?", (args["tag_id"],)).fetchone():
            raise ProviderError("标签不存在", status="not_found")
        selected = source_range(db, args)
        where, params = "tag=?", [args["tag_id"]]
        if selected:
            where += " AND input_id=? AND offset>=? AND offset<?"
            params += [selected["input_id"], selected["offset"], selected["offset"] + selected["length"]]
        rows = db.execute("SELECT input_id,offset FROM origins WHERE " + where + " ORDER BY input_id,offset LIMIT ? OFFSET ?", [*params, limit + 1, cursor]).fetchall()
        return {"tag_id": args["tag_id"], **bounded_page([dict(r) for r in rows], limit, cursor)}
    if kind == "inputs":
        where, params = ["kind='input'", "line> ?"], [cursor]
        if "input_id" in args:
            where.append("input_id=?")
            params.append(args["input_id"])
        if "tid" in args:
            where.append("tid=?")
            params.append(args["tid"])
        if ("offset" in args or "length" in args) and "input_id" not in args:
            raise ProviderError("输入字节切片需要 input_id")
        if "input_id" in args and ("offset" in args or "length" in args):
            source_range(db, args)
        rows = db.execute("SELECT * FROM records WHERE " + " AND ".join(where) + " ORDER BY line LIMIT ?", [*params, limit + 1]).fetchall()
        items = []
        for row in rows:
            r = evidence(db, row)
            start = args.get("offset", 0)
            length = args.get("length", min(128, max(0, r["stored"] - start)))
            # Explicit reads remain bounded; use offsets for the next portion.
            length = min(length, 4096)
            chunks, captured, fragments_truncated = [], 0, False
            for chunkrow in db.execute("SELECT line,payload FROM records WHERE kind='input_chunk' AND input_id=? ORDER BY line", (r["id"],)):
                c = json.loads(chunkrow["payload"])
                begin, end = max(start, c["offset"]), min(start + length, c["offset"] + len(c["bytes"]) // 2)
                if end > begin:
                    if len(chunks) >= 64:
                        fragments_truncated = True
                        length = begin - start
                        break
                    chunks.append({"line": chunkrow["line"], "offset": begin, "address": hex(c["address"] + begin - c["offset"]),
                                   "bytes": c["bytes"][2 * (begin - c["offset"]):2 * (end - c["offset"])]})
                    captured += end - begin
            r.update(chunks=chunks, byte_window={"offset": start, "length": length, "captured": captured,
                     "complete": captured == length, "fragments_truncated": fragments_truncated,
                     "next_offset": start + length if start + length < r["stored"] else None})
            items.append(r)
    else:
        mapping = {"instructions": "instruction", "tags": "tag", "diagnostics": None}
        where = ["r.line>?"]
        params = [cursor]
        if kind == "diagnostics":
            dtype = args.get("diagnostic_type", "dynamic")
            conservative = "(r.kind IN ('step','control','model') AND json_extract(r.payload,'$.policy')='conservative')"
            where.append("(r.kind='gap' OR " + conservative + ")" if dtype == "dynamic" else conservative if dtype == "conservative" else "r.kind=?")
            if dtype in ("gap", "unsupported_static"):
                params.append(dtype)
        else:
            where.append("r.kind=?")
            params.append(mapping[kind])
        for key in ("image", "routine"):
            if key in args:
                where.append(f"instr(json_extract(r.payload,'$.{key}'),?)>0")
                params.append(args[key])
        if "instruction_id" in args:
            where.append("json_extract(r.payload,'$.id')=?")
            params.append(args["instruction_id"])
        selected = source_range(db, args)
        if selected:
            where.append("EXISTS (SELECT 1 FROM origins o WHERE o.tag=json_extract(r.payload,'$.id') AND o.input_id=? AND o.offset>=? AND o.offset<?)")
            params.extend([selected["input_id"], selected["offset"], selected["offset"] + selected["length"]])
        rows = db.execute("SELECT r.* FROM records r WHERE " + " AND ".join(where) + " ORDER BY r.line LIMIT ?", [*params, limit + 1]).fetchall()
        items = [evidence(db, r, expand=False) for r in rows]
    result = bounded_page(items, limit)
    result["next_cursor"] = result["items"][-1]["line"] if result["truncated"] and result["items"] else None
    return result


def aggregate(db, args, *, paginate=True):
    where, params, selected = event_filter(db, args, include_source=False)
    selected = source_range(db, args)
    where += " AND r.kind IN ('input','step','control')"
    if selected:
        where += " AND EXISTS (SELECT 1 FROM origins o WHERE o.tag=u.tag AND o.input_id=? AND o.offset>=? AND o.offset<?)"
        params += [selected["input_id"], selected["offset"], selected["offset"] + selected["length"]]
    if args.get("role", "any") != "any":
        where += " AND u.role=?"
        params.append(args["role"])
    sql = ("SELECT MIN(r.ins) ins,r.input_id,i.image,i.offset image_offset,i.routine,COUNT(DISTINCT r.line) events,"
           "COUNT(DISTINCT CASE WHEN " + ADDRESS_ONLY_SQL + " THEN r.line END) address_only_events,"
           "GROUP_CONCAT(DISTINCT r.ins) instruction_ids,"
           "MAX(CASE u.role WHEN 'control' THEN 3 WHEN 'length' THEN 3 WHEN 'address' THEN 2 ELSE 1 END) priority,"
           "GROUP_CONCAT(DISTINCT u.role) roles,MIN(r.seq) first_seq,MAX(r.seq) last_seq,"
           "COUNT(DISTINCT CASE WHEN r.kind='control' AND json_extract(r.payload,'$.taken') THEN r.line END) taken,"
           "COUNT(DISTINCT CASE WHEN r.kind='control' AND NOT json_extract(r.payload,'$.taken') THEN r.line END) not_taken "
           "FROM records r JOIN uses u ON u.line=r.line LEFT JOIN instructions i ON i.id=r.ins WHERE " + where +
           " GROUP BY i.image,i.offset,json_extract(i.payload,'$.ip'),json_extract(i.payload,'$.asm'),r.input_id "
           "ORDER BY priority DESC,(i.image=?) DESC,events DESC,first_seq,MIN(r.ins)")
    params.append(args.get("_main_image") or "")
    if paginate:
        sql += " LIMIT ? OFFSET ?"
        params += [args.get("limit", 20) + 1, args.get("cursor", 0)]
    result = []
    for row in db.execute(sql, params):
        d = dict(row)
        # r.input_id identifies the event's read, not the source of instruction tags.
        d["event_input_id"] = d.pop("input_id")
        d["input_id"] = selected["input_id"] if selected else None
        d["source_selection"] = selected
        d["routine_source"] = "pin_symbol_hint"
        d["routine_verified"] = False
        d["possible_address_only"] = bool(d["address_only_events"])
        d["instruction_ids"] = sorted(int(x) for x in (d["instruction_ids"] or "").split(",") if x)
        d["roles"] = sorted(d["roles"].split(","))
        if selected:
            source_ids = [selected["input_id"]]
        else:
            ids = d["instruction_ids"]
            identity_filter = "r.ins IN (" + ",".join("?" for _ in ids) + ")" if ids else "r.ins IS NULL"
            source_ids = [row[0] for row in db.execute(
                "SELECT DISTINCT o.input_id FROM records r JOIN uses u ON u.line=r.line JOIN origins o ON o.tag=u.tag "
                "WHERE r.seq>=? AND r.seq<=? AND " + identity_filter + " ORDER BY o.input_id LIMIT 17",
                (d["first_seq"], d["last_seq"], *ids))]
        d["source_input_ids"] = source_ids[:16]
        d["source_input_ids_truncated"] = len(source_ids) > 16
        if not selected and len(source_ids) == 1:
            d["input_id"] = source_ids[0]
        if d["ins"]:
            definition = payload(db, "instructions", d["ins"])
            d["asm"] = definition["asm"][:512]
            d["asm_truncated"] = len(definition["asm"]) > 512
            d["runtime_address"] = hex(definition["ip"])
        d["next_call"] = {"tool": "track_explain", "arguments": {"trace_id": args.get("trace_id"), "seq": d["first_seq"]}}
        result.append(d)
    return result, selected


def influence(db, args):
    items, selected = aggregate(db, args)
    result = bounded_page(items, args.get("limit", 20), args.get("cursor", 0))
    result["source_selection"] = selected
    result["ranking"] = "优先控制转移/接收长度，其次地址、数据；同类优先主目标再按次数排序，不是漏洞评分。"
    result["grouping"] = "相同镜像、运行地址、偏移和反汇编合并；instruction_ids 列出原始 ID（兼容旧日志重复定义）。"
    return result


def origin_view(db, ids, limit):
    ids = sorted(set(ids) - {0})
    if not ids:
        return {"tag_ids": [], "origins": [], "source_byte_count": 0, "truncated": False}
    marks = ",".join("?" for _ in ids)
    rows = db.execute(f"SELECT DISTINCT input_id,offset FROM origins WHERE tag IN ({marks}) ORDER BY input_id,offset LIMIT ?", [*ids, limit + 1]).fetchall()
    count = db.execute(f"SELECT COUNT(*) FROM (SELECT DISTINCT input_id,offset FROM origins WHERE tag IN ({marks}))", ids).fetchone()[0]
    return {"tag_ids": ids, "origins": [{"input_id": r[0], "offset": r[1]} for r in rows[:limit]],
            "source_byte_count": count,
            "precision_note": "来源并集包含多个字节，不能据此认定每个字节都决定本次分支/数值。" if count > 1 else None,
            "truncated": len(rows) > limit,
            "note": "来源按 input_id/offset 排序；大集合可通过 track_query(kind=tags,input_id,offset,length) 定位标签。" if len(rows) > limit else None}


def elf_location(definition, manifest):
    location = {"image": definition["image"], "runtime_address": hex(definition["ip"]),
                "image_offset": hex(definition["image_offset"]), "ghidra_address_verified": False}
    target = manifest.get("target_path")
    if target != definition["image"] or not manifest.get("target_unchanged"):
        location["note"] = "仅有采集时镜像坐标；无法验证模块文件身份，请按实际加载模块映射。"
        return location
    try:
        from tools.track.store import digest
        if digest(target) != manifest.get("target_sha256"):
            raise ValueError("target changed since collection")
        with open(target, "rb") as f:
            header = f.read(64)
            if header[:6] != b"\x7fELF\x02\x01":
                raise ValueError("unsupported ELF")
            phoff = struct.unpack_from("<Q", header, 32)[0]
            entsize, count = struct.unpack_from("<HH", header, 54)
            if entsize != 56 or count > 4096:
                raise ValueError("invalid program headers")
            loads = []
            for index in range(count):
                f.seek(phoff + index * entsize)
                p = struct.unpack("<IIQQQQQQ", f.read(56))
                if p[0] == 1:
                    loads.append(p)
            base = min(p[3] & ~4095 for p in loads)
            address = base + definition["image_offset"]
            if not any(p[3] <= address < p[3] + p[6] and p[1] & 1 for p in loads):
                raise ValueError("address outside executable PT_LOAD")
        location.update(elf_virtual_address=hex(address), elf_image_base=hex(base), target_sha256=manifest["target_sha256"],
                        note="基于一致目标 ELF 的装载段换算；Ghidra 工程若已重定位，需按实际 image base 再换算。")
    except (OSError, ValueError, struct.error) as exc:
        location["note"] = str(exc)
    return location


def explain(db, args, manifest):
    row = db.execute("SELECT * FROM records WHERE seq=?", (args["seq"],)).fetchone()
    if row is None:
        raise ProviderError("事件不在已验证日志前缀中", status="not_found")
    result = evidence(db, row)
    if result["type"] == "model":
        result["return_sources"] = origin_view(db, [result["return_tag"]], args.get("origin_limit", 32))
    if result["type"] == "output":
        result["output_sources"] = origin_view(db, result["tags"], args.get("origin_limit", 32))
    result["provenance_scope"] = "before_origins/after_origins 是现有传播模型的来源集合，可能包含先前注入的地址历史。下游已合并的标签不能事后拆成纯数据与纯地址流；加载事件单列本次选址及注入分量。"
    raw = json.loads(row["payload"])
    limit = args.get("origin_limit", 32)
    if raw["type"] == "input":
        if "operand" in args:
            raise ProviderError("input 事件没有 operand")
        result["length_origins"] = origin_view(db, [raw["length_tag"]], limit)
        result["length_coverage"] = "仅标量接收 RDX；readv/recvmsg 的 length_tag=0 不代表已证明无依赖。"
        return result
    if raw["type"] in ("model", "output"):
        if "operand" in args:
            raise ProviderError("model/output 事件没有指令 operand")
        return result
    definition = payload(db, "instructions", raw["ins"])
    if "operand" in args and args["operand"] >= len(raw["operands"]):
        raise ProviderError("operand 超出事件的操作数范围")
    explanations = []
    used = 0
    for index, (op, spec) in enumerate(zip(raw["operands"], definition["operands"])):
        if "operand" in args and index != args["operand"]:
            continue
        entry = {"index": index, **spec, **hex_addresses(op),
                 "before_origins": origin_view(db, op["before"], limit),
                 "before_is_data_input": spec["read"]}
        if "after" in op:
            entry["after_origins"] = origin_view(db, op["after"], limit)
        if "address_tag" in op:
            entry["address_origins"] = origin_view(db, [op["address_tag"]], limit)
            if spec["read"]:
                entry["load_data_origins"] = entry["before_origins"]
            for field in ("base", "index", "load_address"):
                if field + "_tag" in op:
                    entry[field + "_origins"] = origin_view(db, [op[field + "_tag"]], limit)
            entry["provenance_scope"] = "before/load_data 是加载前内存标签；address 是选址来源，base/index 是机器寻址分量，load_address 是本次注入的分量。内存/寄存器已有标签可能包含更早注入的地址历史，不能事后拆成纯数据来源。"
            if spec["read"] and op["address_tag"] and not any(op["before"]):
                entry["address_only_load"] = True
                entry["address_dependency_note"] = "内存内容无数据标签，但选址依赖输入；默认不传播到加载值。可显式 address_loads=true 采集保守来源。"
        if "value_before" in op:
            entry["value_complete"] = len(op["value_before"]) // 2 == spec["width"]
            if entry["value_complete"] and spec["width"] <= 8:
                entry["unsigned_value_before"] = str(int.from_bytes(bytes.fromhex(op["value_before"]), "little"))
        used += len(json.dumps(entry))
        if used > OUTPUT_BUDGET:
            break
        explanations.append(entry)
    result["operand_explanations"] = explanations
    expected = 1 if "operand" in args else len(raw["operands"])
    result["operands_truncated"] = len(explanations) < expected
    result["location"] = elf_location(definition, manifest)
    if any(s["read"] and s["name"] in ("rflags", "eflags", "gflags") for s in definition["operands"]):
        candidate = None
        for previous in db.execute("SELECT * FROM records WHERE tid=? AND seq<? AND kind IN ('step','control') ORDER BY seq DESC LIMIT 200", (raw["tid"], raw["seq"])):
            ins = payload(db, "instructions", previous["ins"])
            if any(s["write"] and s["name"] in ("rflags", "eflags", "gflags") for s in ins["operands"]):
                candidate = {"seq": previous["seq"], "line": previous["line"], "instruction": preview(ins)}
                break
        result["flag_writer_candidate"] = candidate
        result["flag_writer_scope"] = "仅检索同线程前 200 条已记录指令；整体标志位近似，候选不是已证明的逐标志位定义链。"
    return result


def summary(db, trace_id, manifest):
    q = quality(db)
    hotspots, _ = aggregate(db, {"trace_id": trace_id, "limit": 5, "_main_image": manifest.get("target_path")})
    result = {"trace_id": trace_id, "state": manifest.get("state"), "termination": manifest.get("termination"),
              "collection_outcome": manifest.get("collection_outcome"),
              "stop_request": {"signal": manifest.get("stop_signal"), "at": manifest.get("stop_requested_at"),
                               "scope": "停止请求不证明目标的异步工作已完成；信号 gap 仍按原始证据解释。"} if manifest.get("stop_signal") else None,
              "quality": q, "inputs": query(db, {"kind": "inputs", "limit": 5}),
              "hotspots": hotspots[:5], "diagnostic_preview": query(db, {"kind": "diagnostics", "limit": 5}),
              "next_steps": []}
    source_counts = [dict(r) for r in db.execute("SELECT COALESCE(json_extract(payload,'$.source_kind'),'unknown') source_kind,COUNT(*) reads FROM records WHERE kind='input' GROUP BY source_kind")]
    result["input_source_counts"] = source_counts
    result["input_selection_warnings"] = []
    if manifest.get("options", {}).get("all-reads"):
        result["input_selection_warnings"].append("all_reads=true 有意包含文件/管道读取；请核对 input_id，不要将全部输入当作网络报文。")
    if manifest.get("network_replay") and any(r["source_kind"] != "socket" for r in source_counts):
        result["input_selection_warnings"].append("网络重放期间采到了非 socket 或来源未知的输入；显式 fd 可能指向文件，请先核对输入字节。")
    if q["unpropagated_address_only_events"]:
        policy = "all" if q["address_load_policy"] == "index_only" else "index_only"
        result["next_steps"].append({"reason": "检测到未传播的地址依赖加载；不能由空 control 结果断言无依赖。先核对具体加载；index_only 仍可能漏掉基址依赖，all 会增加指针历史污染。推荐参数仅供确认后重新采集，不自动重跑。",
                                     "tool": "track_explain", "arguments": {"trace_id": trace_id, "seq": q["first_unpropagated_address_seq"]},
                                     "recommended_run_options": {"address_loads": True, "address_load_policy": policy}})
    if not q["structural_complete"] or q["execution_gaps"]:
        result["next_steps"].append({"reason": "先检查缺口；结论仅适用于已记录范围", "tool": "track_query",
                                     "arguments": {"trace_id": trace_id, "kind": "diagnostics"}})
    if not q["counts"].get("input"):
        result["next_steps"].append({"reason": "没有采集到输入：核对 fd/输入驱动/目标读取 API；stdin 通常需 fd=0。"})
    else:
        inp = db.execute("SELECT id,stored FROM inputs ORDER BY id LIMIT 1").fetchone()
        if inp[1]:
            result["next_steps"].append({"reason": "先定位本次输入影响的代码，再解释关键事件", "tool": "track_influence",
                                         "arguments": {"trace_id": trace_id, "input_id": inp[0], "offset": 0, "length": min(inp[1], 1048576)}})
    return result


def compare(left, right, args, left_meta, right_meta):
    if args.get("direction_only") and args.get("role", "any") not in ("any", "control"):
        raise ProviderError("direction_only 只支持 role=any/control")
    def grouped(db, side):
        selection = {"input_id": args[side + "_input_id"], "offset": args.get(side + "_offset", 0)}
        if "length" in args:
            selection["length"] = args["length"]
        else:
            row = db.execute("SELECT stored FROM inputs WHERE id=?", (selection["input_id"],)).fetchone()
            if row is None:
                raise ProviderError("指定 input_id 不存在", status="not_found")
            selection["length"] = row[0] - selection["offset"]
            if not 1 <= selection["length"] <= 1048576:
                raise ProviderError("默认比较剩余输入范围为空或超过 1048576 字节；请显式指定有效 length")
        filters = {k: args[k] for k in ("role", "image", "routine") if k in args}
        if args.get("branch_only") or args.get("direction_only"):
            filters["event_type"] = "control"
        rows, source = aggregate(db, {**selection, **filters, "limit": 50000}, paginate=True)
        # Bound comparisons as well; fail explicitly instead of returning a misleading partial diff.
        if len(rows) > 50000:
            raise ProviderError("比较涉及超过 50000 个位置；请缩小输入字节范围。")
        groups = {}
        receive_lengths = []
        for row in rows:
            row.pop("next_call", None)
            if row["ins"] is None:
                receive_lengths.append(row)
                continue
            key = (row["image"], row["image_offset"])
            if key in groups:
                old = groups[key]
                for field in ("events", "taken", "not_taken"):
                    old[field] += row[field]
                old["roles"] = sorted(set(old["roles"]) | set(row["roles"]))
                old["first_seq"] = min(old["first_seq"], row["first_seq"])
                old["last_seq"] = max(old["last_seq"], row["last_seq"])
            else:
                groups[key] = row
        return groups, source, receive_lengths
    l, ls, ll = grouped(left, "left")
    r, rs, rl = grouped(right, "right")
    verified = bool(left_meta.get("target_sha256") and left_meta.get("target_sha256") == right_meta.get("target_sha256")
                    and left_meta.get("target_unchanged") and right_meta.get("target_unchanged"))
    changed = []
    def directions(row):
        return [name for name in ("taken", "not_taken") if row and row[name]]
    for key in sorted(l.keys() | r.keys(), key=str):
        a, b = l.get(key), r.get(key)
        signature = lambda x: None if x is None else (x["events"], x["roles"], x["taken"], x["not_taken"])
        if signature(a) != signature(b):
            direction_change = a is not None and b is not None and bool(directions(a)) and bool(directions(b)) and directions(a) != directions(b)
            if args.get("direction_only") and not direction_change:
                continue
            is_control = bool(directions(a) or directions(b))
            kind = ("observed_directions" if direction_change else "presence" if a is None or b is None
                    else "control_counts" if is_control else "data_counts_or_roles")
            changed.append({"image": key[0], "image_offset": key[1], "left": a, "right": b,
                            "change_kind": kind, "observed_direction_change": direction_change,
                            "left_directions": directions(a), "right_directions": directions(b),
                            "rank": 0 if direction_change else 1 if kind == "control_counts" else 2 if is_control else 3,
                            "module_identity_verified": verified and key[0] == left_meta.get("target_path") == right_meta.get("target_path")})
    changed.sort(key=lambda x: (x["rank"], x["image"], int(x["image_offset"], 16)))
    cursor, limit = args.get("cursor", 0), args.get("limit", 20)
    result = bounded_page(changed[cursor:cursor + limit + 1], limit, cursor)
    result["range_mode"] = "explicit_equal_length" if "length" in args else "remaining_input_each_side"
    result.update(total_changed_locations=len(changed), left_selection=ls, right_selection=rs,
                  ranking="优先观察到的分支方向集合变化，再控制计数、控制位置增删，最后数据差异。方向集合比较不是动态实例对齐；同集合可能仍有顺序变化。",
                  filters={k: args[k] for k in ("role", "branch_only", "direction_only", "image", "routine") if k in args},
                  receive_lengths_not_aligned={"left_count": len(ll), "right_count": len(rl),
                    "note": "后续读取 ID 没有跨运行对应关系；用各自 track_influence(role=length) 查看。"},
                  comparison_scope="按镜像路径与偏移比较影响位置、分支方向计数；导入轨迹/共享库的模块身份未经验证；读取边界需显式对应。次数变化不是因果证明。")
    return result
