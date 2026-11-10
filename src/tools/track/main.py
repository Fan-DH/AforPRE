"""Track Provider: route operations without coupling indexing to Pin availability."""
import contextlib
import json
import os
import shutil
import uuid

from tools.base import ProviderError
from tools.track import analysis, config as track_config, runner, inspectors, slicing, mapping, path_compare
from tools.track.store import Store, digest, dump, quality


def fingerprint(paths):
    result = []
    for path in paths:
        try:
            s = os.stat(path)
            result.append((path, s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns))
        except OSError:
            result.append((path, None))
    return result


class TrackProvider:
    def __init__(self, config):
        self.config = config
        self.store = Store(config.workspace)
        self.paths = track_config.paths()
        self.fingerprint = fingerprint(self.paths)
        self.stale = False

    def check_environment(self):
        state = track_config.probe_environment()
        self.stale = self.stale or track_config.paths() != self.paths or fingerprint(self.paths) != self.fingerprint
        state["detected_available"] = state["available"]
        state["available"] = state["available"] and not self.stale
        state["runtime"] = {"available": state["available"], "restart_required": self.stale,
                            "reason": "configuration_changed" if self.stale else "ready" if state["available"] else "unavailable"}
        return state

    def _result(self, db, trace_id, data):
        q = quality(db)
        result = {"trace_id": trace_id, **data}
        result.setdefault("quality", q)
        warnings = list(data.get("input_selection_warnings", []))
        if not q["structural_complete"]:
            warnings.append("轨迹不完整或有结构错误；本结果仅覆盖已索引的有效前缀。")
        warnings.extend(issue["message"] for issue in q["semantic_issues"])
        result["limitations"] = warnings
        # A malicious/imported oversized metadata field must not flood the Agent context.
        omitted = {}
        size = len(json.dumps(result, ensure_ascii=False).encode())
        if size > 96000:
            protected = {"trace_id", "quality", "limitations", "line", "seq", "type", "next_cursor", "truncated"}
            for key in sorted(result, key=lambda k: len(json.dumps(result[k])), reverse=True):
                if key in protected:
                    continue
                omitted[key] = len(json.dumps(result[key], ensure_ascii=False).encode())
                del result[key]
                if len(json.dumps(result, ensure_ascii=False).encode()) <= 90000:
                    break
            result["omitted_fields_bytes"] = omitted
            result["limitations"].append("响应超过 96 KB，部分字段省略；缩小 operand/查询范围或导出原始轨迹。")
        return result

    def track_run(self, args):
        return runner.run(self, args)

    def track_import(self, args):
        trace_id = self.store.import_trace(args["path"], args.get("allow_partial", False))
        return self.track_summary({"trace_id": trace_id})

    def track_summary(self, args):
        if "trace_id" not in args:
            items = []
            if self.store.root.exists():
                for path in self.store.root.glob("track-*/manifest.json"):
                    if path.parent.is_symlink():
                        continue
                    m = json.loads(path.read_text())
                    if m.get("state") == "running":
                        from processes import pid_alive
                        from tools.track.store import process_identity
                        if not pid_alive(m.get("pid")) or process_identity(m.get("pid")) != m.get("process_identity"):
                            m["state"] = "interrupted"
                    items.append({k: m.get(k) for k in ("trace_id", "created_at", "state", "termination", "target_path", "source_path")})
            items.sort(key=lambda x: (x["created_at"], x["trace_id"]), reverse=True)
            cursor, limit = args.get("cursor", 0), args.get("limit", 20)
            return analysis.bounded_page(items[cursor:cursor + limit + 1], limit, cursor)
        trace_id = args["trace_id"]
        with contextlib.closing(self.store.open(trace_id)) as db:
            return self._result(db, trace_id, analysis.summary(db, trace_id, self.store.metadata(trace_id)))

    def track_query(self, args):
        with contextlib.closing(self.store.open(args["trace_id"])) as db:
            return self._result(db, args["trace_id"], analysis.query(db, args))

    def track_explain(self, args):
        with contextlib.closing(self.store.open(args["trace_id"])) as db:
            return self._result(db, args["trace_id"], analysis.explain(db, args, self.store.metadata(args["trace_id"])))

    def track_influence(self, args):
        with contextlib.closing(self.store.open(args["trace_id"])) as db:
            options = {**args, "_main_image": self.store.metadata(args["trace_id"]).get("target_path")}
            return self._result(db, args["trace_id"], analysis.influence(db, options))

    def track_compare(self, args):
        with contextlib.closing(self.store.open(args["left_trace_id"])) as left, contextlib.closing(self.store.open(args["right_trace_id"])) as right:
            data = analysis.compare(left, right, args, self.store.metadata(args["left_trace_id"]), self.store.metadata(args["right_trace_id"]))
            data.update(left_quality=quality(left), right_quality=quality(right))
            return data

    def _analyze_trace(self, args, function):
        with contextlib.closing(self.store.open(args["trace_id"])) as db:
            return self._result(db, args["trace_id"], function(db, args))

    def track_slice(self, args):
        return self._analyze_trace(args, slicing.backward_slice)

    def track_branches(self, args):
        return self._analyze_trace(args, inspectors.branches)

    def track_path(self, args):
        return self._analyze_trace(args, inspectors.path)

    def track_memory(self, args):
        return self._analyze_trace(args, inspectors.memory)

    def track_values(self, args):
        return self._analyze_trace(args, inspectors.values)

    def track_compare_paths(self, args):
        with contextlib.closing(self.store.open(args["left_trace_id"])) as left, contextlib.closing(self.store.open(args["right_trace_id"])) as right:
            return path_compare.compare_paths(left, right, args, self.store.metadata(args["left_trace_id"]), self.store.metadata(args["right_trace_id"]))

    def track_map_address(self, args):
        with contextlib.closing(self.store.open(args["trace_id"])) as db:
            return self._result(db, args["trace_id"], mapping.map_address(self, db, args, self.store.metadata(args["trace_id"])))

    def track_export(self, args):
        trace_id = args["trace_id"]
        directory = self.store.directory(trace_id)
        # Opening validates lifecycle before copying a supposedly immutable artifact.
        with contextlib.closing(self.store.open(trace_id)) as db:
            q = quality(db)
            fmt = args.get("format", "raw")
            if fmt == "raw" and "query" in args:
                raise ProviderError("raw 导出不接受 query；筛选报告使用 json/jsonl")
            query_args = {"trace_id": trace_id, **args.get("query", {"kind": "events"})}
            report = self._result(db, trace_id, analysis.query(db, query_args)) if fmt != "raw" else None
            exports = directory / "exports"
            exports.mkdir(exist_ok=True)
            path = exports / (uuid.uuid4().hex + (".json" if fmt == "json" else ".jsonl"))
            if fmt == "raw":
                shutil.copyfile(directory / "trace.jsonl", path)
            elif fmt == "json":
                dump(path, report)
            else:
                with path.open("w", encoding="utf-8") as f:
                    f.write(json.dumps({"type": "apre_track_query_report", **{k: v for k, v in report.items() if k != "items"}}, ensure_ascii=False) + "\n")
                    for item in report["items"]:
                        f.write(json.dumps({"type": "evidence", "record": item}, ensure_ascii=False) + "\n")
            return {"trace_id": trace_id, "path": str(path), "sha256": digest(path), "bytes": path.stat().st_size,
                    "quality": q, "format": fmt, "report_truncated": report.get("truncated") if report else None,
                    "next_cursor": report.get("next_cursor") if report else None,
                    "limitations": ["导出为服务端文件；json/jsonl 查询报告不是完整 schema 1 轨迹。"]}
