"""Own target lifecycle and budgets; never equate tool exit with complete evidence."""
from __future__ import annotations

import contextlib
import os
from pathlib import Path
import signal
import subprocess
import time

from tools.base import ProviderError
from processes import track_process
from tools.track import replay
from tools.track.store import build_index, digest, dump, hexbytes, process_identity


class OutputLimit(Exception):
    pass


def stop(process):
    if process is None:
        return
    # Also terminate remaining descendants when the process-group leader exited.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        if sig == signal.SIGTERM:
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
    process.wait(timeout=5)


def tail(path, size=4096):
    try:
        with path.open("rb") as f:
            f.seek(max(0, path.stat().st_size - size))
            return f.read(size).decode("utf-8", errors="replace")
    except OSError:
        return ""


def replay_preview_item(item):
    return {**item, **({"send_chunks": item["send_chunks"][:8],
                       "send_chunks_count": len(item["send_chunks"]),
                       "send_chunks_truncated": len(item["send_chunks"]) > 8} if "send_chunks" in item else {}), "send_hex": item["send_hex"][:256], "received_hex": item["received_hex"][:256],
            "send_bytes": len(item["send_hex"]) // 2, "received_bytes": len(item["received_hex"]) // 2,
            "send_preview_bytes": min(128, len(item["send_hex"]) // 2),
            "received_preview_bytes": min(128, len(item["received_hex"]) // 2),
            "preview_truncated": len(item["send_hex"]) > 256 or len(item["received_hex"]) > 256,
            "response_truncated": item.get("response_truncated", False)}


def run(provider, args):
    state = provider.check_environment()
    if not state["available"]:
        raise ProviderError("track 采集环境未就绪；先查看 check_engines 的 track 条目。", data=state)
    target = Path(args["target_path"]).resolve()
    try:
        with target.open("rb") as f:
            h = f.read(20)
        if h[:6] != b"\x7fELF\x02\x01" or h[18:20] != b"\x3e\x00":
            raise ValueError("track 仅支持 Linux x86-64 小端 ELF")
        if not os.access(target, os.X_OK):
            raise ValueError("目标文件不可执行")
    except (OSError, ValueError) as exc:
        raise ProviderError(str(exc)) from exc
    if "stdin_hex" in args and "stdin_path" in args:
        raise ProviderError("stdin_hex 与 stdin_path 二选一")
    env = dict(os.environ)
    for key, value in args.get("env", {}).items():
        if not isinstance(key, str) or not key or "=" in key or "\x00" in key or not isinstance(value, str) or "\x00" in value:
            raise ProviderError("env 必须为无 NUL 的字符串键值映射；键不能含 =")
        env[key] = value
    env["LD_BIND_NOW"] = "1"
    cwd = Path(args.get("cwd") or os.getcwd()).resolve()
    if not cwd.is_dir():
        raise ProviderError("cwd 不是目录")
    if any("\x00" in x for x in args.get("args", [])):
        raise ProviderError("目标参数不能含 NUL")
    stdin_data = hexbytes(args["stdin_hex"], "stdin_hex") if "stdin_hex" in args else None
    if stdin_data is not None and len(stdin_data) > 16777216:
        raise ProviderError("stdin_hex 最多 16 MiB；大输入使用 stdin_path")
    if args.get("stop_after_exchanges") and "network" not in args:
        raise ProviderError("stop_after_exchanges 需要 network 重放")
    if "address_load_policy" in args and not args.get("address_loads"):
        raise ProviderError("address_load_policy 需要 address_loads=true")
    if "network" in args:
        replay.validate(args["network"])
    source_stdin = Path(args["stdin_path"]).resolve() if "stdin_path" in args else None
    if source_stdin and not source_stdin.is_file():
        raise ProviderError("stdin_path 不是普通文件")
    pin, plugin = provider.paths
    options = {"fd": args.get("fd", -1), "all-reads": int(args.get("all_reads", False)),
               "values": int(args.get("values", True)), "flow": int(args.get("flow", True)),
               "strict": int(args.get("strict", False)), "address-loads": int(args.get("address_loads", False)), "max-input": args.get("max_input", 1048576),
               "max-events": args.get("max_events", 100000)}
    options["comparison-models"] = int(args.get("comparison_models", True))
    options["address-load-policy"] = args.get("address_load_policy", "all")
    trace_id, directory = provider.store.create(state="preparing", target_path=str(target),
        target_sha256=digest(target), options=options, timeout=args.get("timeout", 30),
        max_output_mb=args.get("max_output_mb", 256), cwd=str(cwd), args=args.get("args", []),
        network_replay="network" in args, ld_bind_now="1", pin_path=pin, plugin_path=plugin, plugin_sha256=digest(plugin))
    trace = directory / "trace.jsonl"
    command = [pin, "-t", plugin, "-o", str(trace)]
    stop_marker = directory / "replay-stop.marker"
    if args.get("stop_after_exchanges"):
        command += ["-stop-marker", str(stop_marker)]
    for key, value in options.items():
        command += ["-" + key, str(value)]
    command += ["--", str(target), *args.get("args", [])]
    stdout, stderr = directory / "stdout.log", directory / "stderr.log"
    transcript = []
    proc = None
    termination, error = "exited", None
    deadline = time.monotonic() + args.get("timeout", 30)

    def check():
        if time.monotonic() >= deadline:
            raise TimeoutError("采集总运行时限已到")
        total = sum(p.stat().st_size for p in (trace, stdout, stderr) if p.exists())
        if total > args.get("max_output_mb", 256) * 1024 * 1024:
            raise OutputLimit("采集日志达到 max_output_mb")

    try:
        with contextlib.ExitStack() as stack:
            if stdin_data is not None:
                input_path = directory / "stdin.bin"
                input_path.write_bytes(stdin_data)
                stdin = stack.enter_context(input_path.open("rb"))
            elif source_stdin:
                # Snapshot input to keep a reproducible artifact even if the original changes later.
                import shutil
                input_path = directory / "stdin.bin"
                shutil.copyfile(source_stdin, input_path)
                stdin = stack.enter_context(input_path.open("rb"))
            else:
                stdin = subprocess.DEVNULL
            out = stack.enter_context(stdout.open("wb"))
            err = stack.enter_context(stderr.open("wb"))
            proc = subprocess.Popen(command, stdin=stdin, stdout=out, stderr=err, cwd=cwd,
                                    env=env, start_new_session=True)
            track_process(proc)
            provider.store.update(trace_id, state="running", pid=proc.pid, process_identity=process_identity(proc.pid))
            if "network" in args:
                replay.replay(args["network"], deadline, check, transcript)
                if args.get("stop_after_exchanges") and proc.poll() is None:
                    # Give asynchronous request processing a bounded settling window.
                    settle = time.monotonic() + args.get("replay_settle_ms", 100) / 1000
                    while proc.poll() is None and time.monotonic() < settle:
                        check()
                        time.sleep(min(0.02, max(0, settle - time.monotonic())))
                    if proc.poll() is None:
                        check()
                        termination = "replay_complete"
                        provider.store.update(trace_id, stop_requested_at=time.time(), stop_signal="SIGTERM")
                        stop_marker.write_text("replay_complete\n")
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
            while proc.poll() is None:
                check()
                try:
                    proc.wait(timeout=min(0.2, max(0.001, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    pass
            # Catch a target that exceeded the disk budget immediately before exiting.
            total = sum(p.stat().st_size for p in (trace, stdout, stderr) if p.exists())
            if total > args.get("max_output_mb", 256) * 1024 * 1024:
                raise OutputLimit("采集日志达到 max_output_mb")
    except TimeoutError as exc:
        termination, error = "timeout", str(exc)
    except OutputLimit as exc:
        termination, error = "output_limit", str(exc)
    except Exception as exc:
        termination, error = "execution_error", str(exc)
    except BaseException:
        termination, error = "cancelled", "worker 被取消；已有轨迹保留"
        raise
    finally:
        stop(proc)
        dump(directory / "replay.json", {"network": args.get("network"), "exchanges": transcript,
                                       "note": "发送段不等于目标读取/应用报文边界。"})
        provider.store.update(trace_id, state="finished" if error is None else "interrupted",
                              termination=termination, error=error, exit_code=proc.returncode if proc else None,
                              finished_at=time.time(), target_unchanged=target.is_file() and digest(target) == provider.store.metadata(trace_id)["target_sha256"])
    q = build_index(directory)
    if trace.exists():
        provider.store.update(trace_id, trace_sha256=digest(trace))
    success = error is None and proc is not None and proc.returncode == 0 and q["structural_complete"]
    outcome = ("timeout_with_complete_trace" if termination == "timeout" and q["structural_complete"]
               else "replay_complete" if termination == "replay_complete" and success
               else "complete" if success else "failed")
    provider.store.update(trace_id, collection_outcome=outcome, state="finished" if success else "interrupted")
    result = provider.track_summary({"trace_id": trace_id})
    replay_preview = [replay_preview_item(item) for item in transcript[:8]]
    result.update(exit_code=proc.returncode if proc else None, artifact_directory=str(directory),
                  stdout_tail=tail(stdout), stderr_tail=tail(stderr), replay=replay_preview,
                  replay_truncated=len(transcript) > 8,
                  artifacts={"trace": str(trace), "stdout": str(stdout), "stderr": str(stderr), "replay": str(directory / "replay.json")})
    if not success:
        message = error or f"采集未完整成功：退出码 {proc.returncode if proc else None}；请检查 quality 与 stderr_tail"
        raise ProviderError(message, status="timeout" if termination == "timeout" else "error", data=result,
                            limitations=["本次真实运行已发生；保留的轨迹可能只覆盖部分执行，不要因失败自动重跑。"],
                            diagnostics=[{"code": "track.collection_failed", "severity": "error", "message": message,
                                          "details": {"trace_id": trace_id, "termination": termination}, "suggestions": ["先查询 track_summary / track_query diagnostics。"]}])
    return result
