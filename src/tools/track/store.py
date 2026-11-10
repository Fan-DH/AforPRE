"""Immutable trace artifacts and a streaming SQLite evidence index (stdlib only)."""
from __future__ import annotations

import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import time
import uuid

from tools.base import ProviderError

INDEX_VERSION = 2
MAX_LINE = 16 * 1024 * 1024
KINDS = {"header", "input", "input_chunk", "tag", "instruction", "step", "control",
         "unsupported_static", "gap", "summary", "model", "output"}
SEMANTICS = [
    "记录显式字节来源及可选、单独标注的比较函数返回值模型；算术和整体标志位可能过度标记，modeled 不代表逐位精确。",
    "value_before 是执行前值；after 是预计写入的标签；故障/信号后不保证回滚。",
    "input_id 是一次成功读取；seq 是回调锁观察顺序，不是跨线程 CPU 全局顺序。",
    "无一般隐式流、跨进程或完整 ISA 保证；未观察到影响不证明不存在影响。",
    "routine 为 Pin 符号提示，stripped/IFUNC 库可能误归属；优先使用 image+image_offset。",
    "向量字节比较可按 lane 传播，但掩码压缩/整体标志位仍可能合并来源，来源并集不是逐字节因果证明。",
]

# Operands must be read memory operands, not stale destination tags or writes.
ADDRESS_ONLY_BODY = """FROM json_each(r.payload,'$.operands') op
    JOIN json_each(i.payload,'$.operands') spec ON spec.key=op.key
    WHERE json_extract(spec.value,'$.read')=1 AND json_extract(op.value,'$.address') IS NOT NULL
    AND json_extract(op.value,'$.address_tag')>0
    AND NOT EXISTS (SELECT 1 FROM json_each(op.value,'$.before') b WHERE b.value!=0)"""
ADDRESS_ONLY_SQL = "EXISTS (SELECT 1 " + ADDRESS_ONLY_BODY + ")"
UNPROPAGATED_SQL = "EXISTS (SELECT 1 " + ADDRESS_ONLY_BODY + """
    AND COALESCE(json_extract(op.value,'$.load_address_tag'),
        CASE WHEN json_extract(r.payload,'$.address_to_data')=1
             THEN json_extract(op.value,'$.address_tag') ELSE 0 END)=0)"""


def observed_quality(db):
    row = db.execute("SELECT COUNT(CASE WHEN " + ADDRESS_ONLY_SQL + " THEN 1 END),"
                     "COUNT(CASE WHEN " + UNPROPAGATED_SQL + " THEN 1 END),"
                     "MIN(CASE WHEN " + UNPROPAGATED_SQL + " THEN r.seq END) "
                     "FROM records r JOIN instructions i ON i.id=r.ins WHERE r.kind IN ('step','control')").fetchone()
    termination = db.execute("SELECT COUNT(*) FROM records WHERE kind='gap' "
                             "AND json_extract(payload,'$.category')='expected_stop' "
                             "AND json_extract(payload,'$.classification_basis')='replay_stop_marker' "
                             "AND json_extract(payload,'$.signal_or_exception')=15").fetchone()[0]
    return {"address_only_load_events": row[0], "unpropagated_address_only_events": row[1],
            "first_unpropagated_address_seq": row[2], "termination_gaps": termination}


def dump(path, value):
    tmp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def number(value, name, minimum=0, maximum=(1 << 64) - 1):
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{name}: integer outside [{minimum}, {maximum}]")
    return value


def hexbytes(value, name):
    if not isinstance(value, str) or len(value) % 2 or re.fullmatch(r"[0-9a-fA-F]*", value) is None:
        raise ValueError(f"{name}: expected even-length hexadecimal bytes")
    return bytes.fromhex(value)


class Store:
    def __init__(self, workspace):
        self.root = Path(workspace).resolve() / "artifacts" / "track"

    def create(self, **metadata):
        self.root.mkdir(parents=True, exist_ok=True)
        trace_id = "track-" + uuid.uuid4().hex
        directory = self.root / trace_id
        directory.mkdir()
        dump(directory / "manifest.json", {"trace_id": trace_id, "created_at": time.time(), **metadata})
        return trace_id, directory

    def directory(self, trace_id):
        if re.fullmatch(r"track-[0-9a-f]{32}", trace_id) is None:
            raise ProviderError("无效的 trace_id")
        directory = self.root / trace_id
        if directory.is_symlink() or not directory.is_dir():
            raise ProviderError("轨迹不存在", status="not_found")
        return directory

    def metadata(self, trace_id):
        return json.loads((self.directory(trace_id) / "manifest.json").read_text())

    def update(self, trace_id, **values):
        m = self.metadata(trace_id)
        m.update(values)
        dump(self.directory(trace_id) / "manifest.json", m)
        return m

    def open(self, trace_id):
        directory = self.directory(trace_id)
        metadata = self.metadata(trace_id)
        if metadata.get("state") == "running":
            pid = metadata.get("pid")
            from processes import pid_alive
            # PID alone is insufficient; compare Linux process start identity.
            if pid and pid_alive(pid) and process_identity(pid) == metadata.get("process_identity"):
                raise ProviderError("采集仍在运行，日志缓冲尚未完整落盘；先 job_status 等待结束。")
            self.update(trace_id, state="interrupted", termination="worker_or_target_disappeared")
        index = directory / "index.sqlite"
        if not index.exists():
            build_index(directory)
        db = sqlite3.connect(index.as_uri() + "?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        if json.loads(db.execute("SELECT value FROM meta WHERE key='version'").fetchone()[0]) != INDEX_VERSION:
            db.close()
            raise ProviderError("轨迹索引版本不兼容，请重新导入原始日志。")
        return db

    def import_trace(self, path, allow_partial=False):
        source = Path(path).resolve()
        if not source.is_file():
            raise ProviderError("轨迹源文件不存在", status="not_found")
        trace_id, directory = self.create(state="imported", source_path=str(source))
        shutil.copyfile(source, directory / "trace.jsonl")
        q = build_index(directory)
        self.update(trace_id, trace_sha256=digest(directory / "trace.jsonl"))
        if not q["structural_complete"] and not allow_partial:
            raise ProviderError("日志未完整通过结构校验；可用返回的 trace_id 查看诊断，或显式 allow_partial 导入。",
                                data={"trace_id": trace_id, "quality": q})
        return trace_id


def process_identity(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def payload(db, table, key):
    column = "id" if table in ("tags", "instructions") else "line"
    # table is an internal constant, never user SQL.
    row = db.execute(f"SELECT payload FROM {table} WHERE {column}=?", (key,)).fetchone()
    return json.loads(row[0]) if row else None


def quality(db):
    result = json.loads(db.execute("SELECT value FROM meta WHERE key='quality'").fetchone()[0])
    result["structural_complete_scope"] = "仅记录结构、引用、序号及计数完整；不保证语义传播完整或响应处理完成。"
    result["semantics"] = SEMANTICS
    header = db.execute("SELECT payload FROM records WHERE kind='header' LIMIT 1").fetchone()
    metadata = json.loads(header[0]) if header else {}
    result["collector_model_revision"] = metadata.get("model_revision", "legacy_unknown")
    result["comparison_models"] = metadata.get("comparison_models", False)
    result["output_capture"] = metadata.get("output_capture", False)
    result["address_loads"] = metadata.get("address_loads")
    result["address_load_policy"] = metadata.get("address_load_policy", "all" if metadata.get("address_loads") else "off" if metadata.get("address_loads") is False else "unknown")
    observed = db.execute("SELECT value FROM meta WHERE key='observed_quality'").fetchone()
    result.update(json.loads(observed[0]) if observed else observed_quality(db))
    result["execution_gaps"] = result["gaps"] - result["termination_gaps"]
    result["issues_scope"] = "issues 仅列结构校验错误；语义限制另见 semantic_issues。gaps 保留总数，execution_gaps 排除有停止标记的 termination_gaps。"
    semantic = []
    if result["execution_gaps"]:
        semantic.append({"code": "execution_gaps", "count": result["execution_gaps"],
                         "message": "存在执行缺口，影响范围不能视为完整。"})
    if result["termination_gaps"]:
        semantic.append({"code": "expected_stop", "count": result["termination_gaps"],
                         "message": "重放停止标记关联的 SIGTERM 缺口已单列；停止边界仍无回滚保证，不能据此证明解析阶段完整。"})
    if result["unpropagated_address_only_events"]:
        semantic.append({"code": "possible_address_only", "count": result["unpropagated_address_only_events"],
                         "message": "存在带地址来源但无内存数据标签、且未注入地址来源的加载；下游可能漏报，空分支结果不证明没有依赖。"})
    if result["address_loads"]:
        semantic.append({"code": "address_history_union", "message": "地址传播会继承指针/索引历史；来源并集不能解释为当前字节的精确因果。index_only 仅按机器操作数选择索引。"})
    if result["conservative_events"] or result.get("conservative_records_observed"):
        semantic.append({"code": "conservative", "message": "存在保守传播；来源集合可能过度标记。"})
    if result["short_value_reads"]:
        semantic.append({"code": "short_values", "message": "存在运行值短读；不能补零当作完整数值。"})
    if result["comparison_models"]:
        semantic.append({"code": "comparison_abi_summary", "message": "已启用导入的 strcmp/strncmp/memcmp/bcmp 返回值模型：采用比较前缀来源并集，含相等路径；不是一般隐式流，未覆盖内联、自定义或无法识别的调用。"})
    result["semantic_issues"] = semantic
    return result


def build_index(directory):
    """Validate and index a snapshot; salvage only the prefix before the first invalid record."""
    import fcntl
    with (directory / "index.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        existing = directory / "index.sqlite"
        if existing.exists():
            with sqlite3.connect(existing) as db:
                return quality(db)
        temporary = directory / ("index-" + uuid.uuid4().hex + ".tmp")
        db = sqlite3.connect(temporary)
        try:
            q = _index(db, directory / "trace.jsonl")
            db.commit()
            db.close()
            os.replace(temporary, existing)
            return q
        finally:
            db.close()
            temporary.unlink(missing_ok=True)


def _index(db, path):
    db.executescript("""
        CREATE TABLE records(line INTEGER PRIMARY KEY, kind TEXT, seq INTEGER, tid INTEGER,
                             ins INTEGER, input_id INTEGER, target TEXT, payload TEXT);
        CREATE UNIQUE INDEX seq_idx ON records(seq) WHERE seq IS NOT NULL;
        CREATE INDEX kind_idx ON records(kind,line);
        CREATE INDEX ins_idx ON records(ins,line);
        CREATE INDEX thread_seq_idx ON records(tid,seq);
        CREATE INDEX input_idx ON records(input_id,line);
        CREATE TABLE tags(id INTEGER PRIMARY KEY, payload TEXT);
        CREATE TABLE origins(tag INTEGER, input_id INTEGER, offset INTEGER, PRIMARY KEY(tag,input_id,offset));
        CREATE INDEX origin_idx ON origins(input_id,offset,tag);
        CREATE TABLE instructions(id INTEGER PRIMARY KEY, image TEXT, offset TEXT, routine TEXT, payload TEXT);
        CREATE TABLE uses(line INTEGER, tag INTEGER, role TEXT, PRIMARY KEY(line,tag,role));
        CREATE INDEX uses_tag_idx ON uses(tag,role,line);
        CREATE TABLE inputs(id INTEGER PRIMARY KEY, stored INTEGER);
        CREATE TABLE chunks(input_id INTEGER, start INTEGER, end INTEGER, line INTEGER);
        CREATE INDEX chunk_idx ON chunks(input_id,start,end);
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
        INSERT INTO tags VALUES(0,'{"type":"tag","id":0,"origins":[]}');
    """)
    # Keep per-record savepoints inside one transaction; otherwise each RELEASE
    # would fsync/commit separately and large traces become unnecessarily slow.
    db.execute("BEGIN")
    counts = collections.Counter()
    last_seq = 0
    summary = None
    issues = []
    values_count = short_values = conservative_records = 0
    line_no = 0

    def tag_exists(t):
        number(t, "tag", maximum=(1 << 32) - 1)
        if not db.execute("SELECT 1 FROM tags WHERE id=?", (t,)).fetchone():
            raise ValueError(f"undefined tag {t}")

    try:
        with path.open("rb") as stream:
            while True:
                raw = stream.readline(MAX_LINE + 1)
                if not raw:
                    break
                line_no += 1
                if len(raw) > MAX_LINE:
                    raise ValueError("record exceeds 16 MiB indexing limit")
                r = json.loads(raw)
                if not isinstance(r, dict) or r.get("type") not in KINDS:
                    raise ValueError("unknown or missing record type")
                kind = r["type"]
                if line_no == 1 and (kind != "header" or r.get("schema") != 1 or r.get("architecture") != "linux-x86_64"):
                    raise ValueError("missing linux-x86_64 schema 1 header")
                if kind == "header" and line_no != 1:
                    raise ValueError("duplicate header")
                if summary is not None:
                    raise ValueError("record after final summary")
                if kind in ("input", "step", "control", "model", "output"):
                    number(r["seq"], "seq", 1, (1 << 63) - 1)
                    number(r["tid"], "tid", 0, (1 << 32) - 1)
                    if r["seq"] != last_seq + 1:
                        raise ValueError("non-contiguous dynamic seq")
                elif "seq" in r:
                    raise ValueError("seq on non-dynamic record")
                db.execute("SAVEPOINT record")
                previous_values = values_count, short_values
                try:
                    if kind == "tag":
                        number(r["id"], "tag.id", 1, (1 << 32) - 1)
                        if not isinstance(r["origins"], list) or not r["origins"]:
                            raise ValueError("tag requires nonempty origins")
                        db.execute("INSERT INTO tags VALUES(?,?)", (r["id"], json.dumps(r)))
                        for origin in r["origins"]:
                            if not isinstance(origin, list) or len(origin) != 2:
                                raise ValueError("invalid origin")
                            inp = number(origin[0], "origin.input", 1, (1 << 32) - 1)
                            off = number(origin[1], "origin.offset", 0, (1 << 32) - 1)
                            db.execute("INSERT INTO origins VALUES(?,?,?)", (r["id"], inp, off))
                    elif kind == "instruction":
                        number(r["id"], "instruction.id", 1, (1 << 63) - 1)
                        number(r["ip"], "ip")
                        number(r["image_offset"], "image_offset")
                        for key in ("image", "routine", "asm"):
                            if not isinstance(r[key], str):
                                raise ValueError(f"instruction.{key} must be text")
                        if not isinstance(r["operands"], list) or len(r["operands"]) > 16:
                            raise ValueError("invalid instruction operands")
                        for op in r["operands"]:
                            number(op["width"], "operand.width", 1, 64)
                            if not isinstance(op["name"], str) or any(type(op[k]) is not bool for k in ("read", "write")):
                                raise ValueError("invalid operand metadata")
                        db.execute("INSERT INTO instructions VALUES(?,?,?,?,?)", (r["id"], r["image"], hex(r["image_offset"]), r["routine"], json.dumps(r)))
                    elif kind == "input_chunk":
                        number(r["input"], "input_chunk.input", 1, (1 << 32) - 1)
                        number(r["offset"], "input_chunk.offset", 0, (1 << 32) - 1)
                        number(r["address"], "input_chunk.address")
                        copied = len(hexbytes(r["bytes"], "input_chunk.bytes"))
                        if copied:
                            if db.execute("SELECT 1 FROM chunks WHERE input_id=? AND start<? AND end>? LIMIT 1", (r["input"], r["offset"] + copied, r["offset"])).fetchone():
                                raise ValueError("overlapping input chunks")
                            db.execute("INSERT INTO chunks VALUES(?,?,?,?)", (r["input"], r["offset"], r["offset"] + copied, line_no))
                    elif kind == "input":
                        number(r["id"], "input.id", 1, (1 << 32) - 1)
                        for key in ("fd", "syscall", "returned", "stored", "tainted", "flags"):
                            number(r[key], f"input.{key}", maximum=(1 << 63) - 1)
                        if not r["returned"] or not r["tainted"] <= r["stored"] <= r["returned"]:
                            raise ValueError("invalid input byte counts")
                        tag_exists(r["length_tag"])
                        db.execute("INSERT INTO inputs VALUES(?,?)", (r["id"], r["stored"]))
                        if r["length_tag"]:
                            db.execute("INSERT INTO uses VALUES(?,?,?)", (line_no, r["length_tag"], "length"))
                    elif kind in ("step", "control"):
                        number(r["ins"], "ins", 1, (1 << 63) - 1)
                        definition = payload(db, "instructions", r["ins"])
                        if definition is None:
                            raise ValueError("undefined instruction")
                        if r["policy"] not in ("modeled", "conservative") or not isinstance(r["operands"], list) or len(r["operands"]) != len(definition["operands"]):
                            raise ValueError("invalid policy or operand count")
                        if kind == "control":
                            if type(r["taken"]) is not bool:
                                raise ValueError("taken must be boolean")
                            number(r["target"], "target")
                        for op, spec in zip(r["operands"], definition["operands"]):
                            if not isinstance(op, dict):
                                raise ValueError("event operand must be an object")
                            for key in ("before", "after"):
                                if key == "after" and not spec["write"]:
                                    continue
                                if not isinstance(op.get(key), list) or len(op[key]) != spec["width"]:
                                    raise ValueError("invalid byte tag width")
                                for t in op[key]:
                                    tag_exists(t)
                                    # Old destination tags are context, not evidence that the new value depends on them.
                                    if t and (key == "after" or spec["read"]):
                                        role = "control" if kind == "control" and key == "before" else "data"
                                        db.execute("INSERT OR IGNORE INTO uses VALUES(?,?,?)", (line_no, t, role))
                            if "address" in op:
                                number(op["address"], "address")
                                tag_exists(op["address_tag"])
                                for extra in ("base_tag", "index_tag", "load_address_tag"):
                                    if extra in op:
                                        tag_exists(op[extra])
                                if op["address_tag"]:
                                    db.execute("INSERT OR IGNORE INTO uses VALUES(?,?,?)", (line_no, op["address_tag"], "address"))
                            if "value_before" in op:
                                n = len(hexbytes(op["value_before"], "value_before"))
                                if n > spec["width"]:
                                    raise ValueError("operand value wider than width")
                                values_count += 1
                                short_values += n < spec["width"]
                    elif kind == "model":
                        if r["model"] != "comparison_return" or r["policy"] != "conservative":
                            raise ValueError("unknown semantic model")
                        if r["function"] not in ("strcmp", "strncmp", "memcmp", "bcmp"):
                            raise ValueError("unknown comparison ABI")
                        number(r["return_ip"], "return_ip")
                        number(r["compared_bytes"], "compared_bytes")
                        number(r["result"], "result", -(1 << 31), (1 << 31) - 1)
                        tag_exists(r["return_tag"])
                        if r["return_tag"]:
                            db.execute("INSERT INTO uses VALUES(?,?,?)", (line_no, r["return_tag"], "data"))
                    elif kind == "output":
                        for key in ("fd", "syscall", "offset", "returned", "address"):
                            number(r[key], "output." + key)
                        n = len(hexbytes(r["bytes"], "output.bytes"))
                        if not isinstance(r["tags"], list) or len(r["tags"]) != n or r["offset"] + n > r["returned"]:
                            raise ValueError("invalid output byte range/tags")
                        for tag in r["tags"]:
                            tag_exists(tag)
                            if tag:
                                db.execute("INSERT OR IGNORE INTO uses VALUES(?,?,?)", (line_no, tag, "data"))
                    elif kind == "gap":
                        if not isinstance(r["reason"], str):
                            raise ValueError("gap reason missing")
                        if "ins" in r:
                            number(r["ins"], "gap.ins", 1, (1 << 63) - 1)
                            if payload(db, "instructions", r["ins"]) is None:
                                raise ValueError("gap references undefined instruction")
                    elif kind == "unsupported_static":
                        number(r["ip"], "unsupported.ip")
                        if not isinstance(r["asm"], str):
                            raise ValueError("unsupported.asm must be text")
                    elif kind == "summary":
                        for key in ("events", "inputs", "tags", "gaps", "conservative_events", "shadow_pages"):
                            number(r[key], f"summary.{key}", maximum=(1 << 63) - 1)
                        number(r["exit_code"], "exit_code", -(1 << 31), (1 << 31) - 1)
                        if (r["events"] != last_seq or r["inputs"] != counts["input"] or
                                r["tags"] != counts["tag"] or r["gaps"] != counts["gap"]):
                            raise ValueError("summary counts mismatch")
                    inp = r.get("id") if kind == "input" else r.get("input") if kind == "input_chunk" else None
                    db.execute("INSERT INTO records VALUES(?,?,?,?,?,?,?,?)", (line_no, kind, r.get("seq"), r.get("tid"), r.get("ins"), inp,
                               hex(r["target"]) if kind == "control" else None, json.dumps(r)))
                    db.execute("RELEASE record")
                except Exception:
                    values_count, short_values = previous_values
                    db.execute("ROLLBACK TO record")
                    db.execute("RELEASE record")
                    raise
                counts[kind] += 1
                if kind in ("input", "step", "control", "model", "output"):
                    last_seq = r["seq"]
                if kind == "summary":
                    summary = {k: r[k] for k in ("type", "exit_code", "events", "inputs", "tags", "gaps", "conservative_events", "shadow_pages")}
                if kind in ("step", "control", "model") and r["policy"] == "conservative":
                    conservative_records += 1
    except (OSError, ValueError, KeyError, TypeError, OverflowError, sqlite3.IntegrityError) as exc:
        issues.append({"line": line_no, "message": str(exc)})
    if not counts["header"]:
        issues.append({"line": 1, "message": "missing header"})
    if summary is None:
        issues.append({"line": None, "message": "missing final summary"})
    # Definitions and chunks legitimately precede the input summary; validate after the stream.
    missing = db.execute("SELECT o.input_id,o.offset FROM origins o LEFT JOIN inputs i ON i.id=o.input_id WHERE i.id IS NULL OR o.offset>=i.stored LIMIT 1").fetchone()
    if missing:
        issues.append({"line": None, "message": f"origin outside a recorded input: {tuple(missing)}"})
    missing = db.execute("SELECT o.input_id,o.offset FROM origins o WHERE NOT EXISTS (SELECT 1 FROM chunks c WHERE c.input_id=o.input_id AND c.start<=o.offset AND c.end>o.offset) LIMIT 1").fetchone()
    if missing:
        issues.append({"line": None, "message": f"origin has no captured source byte: {tuple(missing)}"})
    mismatch = db.execute("SELECT r.input_id FROM records r LEFT JOIN (SELECT input_id,SUM(end-start) n FROM chunks GROUP BY input_id) c ON c.input_id=r.input_id WHERE r.kind='input' AND json_extract(r.payload,'$.tainted')!=COALESCE(c.n,0) LIMIT 1").fetchone()
    if mismatch:
        issues.append({"line": None, "message": f"captured input bytes differ from tainted count: {mismatch[0]}"})
    for row in db.execute("SELECT input_id,payload FROM records WHERE kind='input_chunk'"):
        chunk = json.loads(row[1])
        inp = db.execute("SELECT stored FROM inputs WHERE id=?", (row[0],)).fetchone()
        if inp is None or chunk["offset"] + len(chunk["bytes"]) // 2 > inp[0]:
            issues.append({"line": None, "message": "input chunk outside a recorded input"})
            break
    q = {"structural_complete": not issues, "issues": issues, "counts": dict(counts),
         "last_seq": last_seq, "summary": summary, "gaps": counts["gap"],
         "conservative_events": summary.get("conservative_events") if summary else None,
         "conservative_records_observed": conservative_records,
         "values_observed": values_count > 0, "short_value_reads": short_values,
         "semantics": SEMANTICS, "semantic_completeness_proven": False}
    db.execute("INSERT INTO meta VALUES('quality',?)", (json.dumps(q),))
    db.execute("INSERT INTO meta VALUES('observed_quality',?)", (json.dumps(observed_quality(db)),))
    db.execute("INSERT INTO meta VALUES('version',?)", (json.dumps(INDEX_VERSION),))
    return q
