# -*- coding: utf-8 -*-
"""后台作业层：把长耗时工具调用转为可轮询的异步作业。

背景：首次 Ghidra 导入（大目标可达数分钟）、调试会话启动等操作会超过
客户端的请求超时。job_submit 把调用交给独立的 worker 进程执行并立即返回
job_id；客户端用 job_status 轮询状态与最终结果，不再需要“瞎重试”。

设计要点：
  - worker 是与提交进程无关的独立进程（start_new_session），CLI 与 MCP
    提交的作业都能在提交者退出后继续执行；
  - 作业状态落盘 $APRE_WORKSPACE/jobs/<job_id>/：request.json（提交内容）、
    state.json（运行态）、progress.json（心跳）、result.json（最终 ToolResult）、
    worker.log（worker 输出，含记录写入错误等诊断）；
  - worker 使用与正常调用完全相同的 dispatcher/record 链路，作业结果与
    正常调用一样进入 RecordStore（含 record_id）；
  - job_list 自动回收超过 TTL（APRE_JOB_TTL，默认 3600s）的已完成作业，
    以及 worker 异常退出的 running 作业（标记 failed 后回收）。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

from contracts.results import NOT_FOUND
from contracts.tools import get_tool_contract, validate_arguments
from tools.base import ProviderError
from processes import pid_alive as _pid_alive, track_process

JOB_PREFIX = "job-"

_CLI_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "entrypoints", "CLI", "cli.py"))

_REQUEST_FILE = "request.json"
_STATE_FILE = "state.json"
_PROGRESS_FILE = "progress.json"
_RESULT_FILE = "result.json"
_WORKER_LOG = "worker.log"
_WORKER_FILE = "worker.json"

_JOB_STATE_VERSION = 1


class _JobCancelled(BaseException):
    pass


def run_worker(directory: str) -> int:
    """Worker lifecycle; state/results are atomic and cancellation stops children."""
    import threading
    from config import load_config
    from entrypoints.dispatcher import ToolDispatcher
    from records.store import RecordStore
    from tools.composite import CompositeProvider
    from processes import terminate_children

    stopped = threading.Event()
    state_path = os.path.join(directory, _STATE_FILE)
    progress_path = os.path.join(directory, _PROGRESS_FILE)
    state = _read_json(state_path, {})
    started = time.time()

    def write_state(**changes):
        state.update(changes)
        _write_json(state_path, state)

    def cancel(signum, frame):
        # Avoid a second signal interrupting cleanup halfway through.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        terminate_children()
        raise _JobCancelled("作业已取消；已执行的修改不会自动回滚。")

    signal.signal(signal.SIGTERM, cancel)

    def heartbeat():
        while not stopped.wait(2):
            try:
                _write_json(progress_path, {"state": "running", "elapsed_seconds": round(time.time() - started, 1)})
            except OSError:
                pass

    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        request = _read_json(os.path.join(directory, _REQUEST_FILE))
        if not request:
            raise ValueError("作业 request.json 无效")
        write_state(state="running", worker_pid=os.getpid(), started_at=started)
        cfg = load_config()
        dispatcher = ToolDispatcher(CompositeProvider.auto_build(cfg), RecordStore(cfg.workspace))
        result = dispatcher.handle(request["tool"], request["arguments"])
        _write_json(os.path.join(directory, _RESULT_FILE), result.to_dict())
        state.update(state="done", finished_at=time.time(), record_id=result.record_id)
        return 0 if result.status == "ok" else 1
    except (Exception, _JobCancelled) as exc:
        state.update(state="failed", finished_at=time.time(), error=str(exc), exception_type=type(exc).__name__)
        return 1
    finally:
        stopped.set()
        thread.join()
        _write_json(progress_path, {"state": state.get("state"), "elapsed_seconds": round(time.time() - started, 1)})
        # Publish the terminal state last: job_remove may delete the directory
        # immediately once done/failed becomes visible.
        _write_json(state_path, state)


def job_ttl() -> int:
    try:
        value = int(os.environ.get("APRE_JOB_TTL") or "3600")
    except ValueError:
        return 3600
    return value if value > 0 else 3600


def valid_job_id(job_id) -> bool:
    return isinstance(job_id, str) and re.fullmatch(r"job-[0-9a-f]{32}", job_id) is not None


def jobs_root(workspace: str) -> str:
    return os.path.join(os.path.abspath(workspace), "jobs")


def _read_json(path: str, default=None):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.loads(fh.read())
        return data if isinstance(data, dict) else default
    except (OSError, ValueError):
        return default


def _write_json(path: str, data: dict) -> None:
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(temp, path)


class JobManager:
    """提交、查询、清理后台作业。"""

    def __init__(self, workspace: str):
        self.workspace = os.path.abspath(workspace)

    # --- 目录与状态 ---
    def _directory(self, job_id: str) -> str:
        if not valid_job_id(job_id):
            raise ProviderError("作业 ID 格式无效: %r" % (job_id,),
                                limitations=["没有查询或修改任何作业。"])
        directory = os.path.join(jobs_root(self.workspace), job_id)
        if not os.path.isdir(directory):
            raise ProviderError("作业不存在: %s" % job_id, status=NOT_FOUND,
                                limitations=["没有可返回的作业结果；作业可能已被清理，用 job_list 查看当前作业。"])
        return directory

    def _state(self, job_id: str) -> dict:
        directory = self._directory(job_id)
        request = _read_json(os.path.join(directory, _REQUEST_FILE), {})
        state = _read_json(os.path.join(directory, _STATE_FILE),
                           {"state": "unknown"})
        state.setdefault("tool", request.get("tool"))
        state.setdefault("submitted_at", request.get("submitted_at"))
        state.setdefault("arguments", request.get("arguments"))
        state.setdefault("worker_pid", _read_json(os.path.join(directory, _WORKER_FILE), {}).get("pid"))
        return state

    def _mark_worker_dead(self, directory: str, state: dict) -> None:
        """worker 进程消失但作业仍标为 running：标记 failed 并保留日志摘要。"""
        tail = ""
        try:
            with open(os.path.join(directory, _WORKER_LOG), "r",
                      encoding="utf-8", errors="replace") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 2000))
                tail = fh.read()[-2000:]
        except OSError:
            pass
        state.update({"state": "failed", "finished_at": time.time(),
                      "error": "worker 进程异常退出（提交后没有产出结果）。",
                      "worker_log_tail": tail})
        try:
            _write_json(os.path.join(directory, _STATE_FILE), state)
        except OSError:
            pass

    # --- 提交 ---
    def submit(self, tool: str, arguments: dict) -> dict:
        if tool.startswith("job_"):
            raise ProviderError("后台作业不能嵌套执行作业管理工具。")
        contract = get_tool_contract(tool)
        if contract is None:
            raise ProviderError("未知工具: %s（job_submit 只能提交已注册的工具）" % tool,
                                limitations=["没有创建后台作业。"])
        try:
            validate_arguments(contract, arguments)
        except ValueError as exc:
            raise ProviderError("作业参数校验失败: %s" % exc,
                                limitations=["没有创建后台作业。"]) from exc
        job_id = JOB_PREFIX + uuid.uuid4().hex
        directory = os.path.join(jobs_root(self.workspace), job_id)
        try:
            os.makedirs(directory, mode=0o700, exist_ok=False)
        except FileExistsError:
            raise ProviderError("作业 ID 冲突: %s" % job_id,
                                limitations=["没有覆盖已有作业。"])
        except OSError as exc:
            raise ProviderError("无法创建作业目录: %s" % exc,
                                limitations=["作业没有提交。"]) from exc
        request = {"version": _JOB_STATE_VERSION, "job_id": job_id, "tool": tool,
                   "arguments": dict(arguments), "submitted_at": time.time()}
        env = dict(os.environ)
        env["APRE_WORKSPACE"] = self.workspace
        env["APRE_JOB_DIR"] = directory
        log_path = os.path.join(directory, _WORKER_LOG)
        try:
            log_fh = open(log_path, "ab")
        except OSError as exc:
            shutil.rmtree(directory, ignore_errors=True)
            raise ProviderError("无法打开作业日志: %s" % exc,
                                limitations=["作业没有提交。"]) from exc
        try:
            _write_json(os.path.join(directory, _REQUEST_FILE), request)
            # The worker owns state updates after spawn; the parent must never
            # overwrite a fast worker's completed state with 'running'.
            _write_json(os.path.join(directory, _STATE_FILE), {
                "version": _JOB_STATE_VERSION, "state": "starting", "tool": tool,
                "submitted_at": request["submitted_at"], "arguments": dict(arguments)})
            proc = subprocess.Popen(
                [sys.executable, "-B", _CLI_PATH, "__run_job__", directory],
                stdin=subprocess.DEVNULL, stdout=log_fh, stderr=subprocess.STDOUT,
                start_new_session=True, env=env,
            )
        except OSError as exc:
            try:
                _write_json(os.path.join(directory, _STATE_FILE), {
                    "state": "failed", "finished_at": time.time(), "error": str(exc)})
            except OSError:
                pass
            raise ProviderError("作业 worker 启动失败: %s" % exc,
                                limitations=["作业已记录但未执行；用 job_remove 清理后重新提交。"],
                                data={"job_id": job_id, "directory": directory}) from exc
        finally:
            log_fh.close()
        track_process(proc)
        limitations = []
        try:
            _write_json(os.path.join(directory, _WORKER_FILE), {"pid": proc.pid})
        except OSError as exc:
            limitations.append("worker 已启动，但 PID 元数据写入失败: %s；不要盲目重新提交。" % exc)
        return {"job_id": job_id, "state": "running", "tool": tool,
                "worker_pid": proc.pid, "directory": directory,
                "limitations": limitations,
                "note": "用 job_status 轮询结果（可传 wait 秒数）；作业在提交者退出后继续执行。"}

    # --- 查询 ---
    def status(self, job_id: str, wait: int = 0) -> dict:
        directory = self._directory(job_id)
        deadline = time.monotonic() + max(0, int(wait))
        while True:
            state = self._state(job_id)
            if state.get("state") in ("running", "starting") and state.get("worker_pid") and not _pid_alive(state["worker_pid"]):
                self._mark_worker_dead(directory, state)
                break
            if state.get("state") not in ("running", "starting", "unknown"):
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.2)
        state = self._state(job_id)
        result = {
            "job_id": job_id,
            "state": state.get("state", "unknown"),
            "tool": state.get("tool"),
            "worker_pid": state.get("worker_pid"),
            "submitted_at": state.get("submitted_at"),
            "finished_at": state.get("finished_at"),
            "elapsed_seconds": round(float(state.get("finished_at") or time.time()) -
                                     float(state.get("submitted_at") or time.time()), 1),
            "progress": _read_json(os.path.join(directory, _PROGRESS_FILE), {}),
            "worker_log_path": os.path.join(directory, _WORKER_LOG),
        }
        if result["state"] == "done":
            result["result"] = _read_json(os.path.join(directory, _RESULT_FILE))
        elif result["state"] == "failed":
            result["error"] = state.get("error")
            result["worker_log_tail"] = state.get("worker_log_tail")
        result["log_hint"] = self._log_hint(state)
        return result

    def list(self) -> dict:
        root = jobs_root(self.workspace)
        jobs, reaped = [], []
        try:
            entries = sorted(os.listdir(root))
        except OSError:
            return {"jobs": jobs, "count": 0, "reaped": reaped, "reaped_count": 0}
        now = time.time()
        for name in entries:
            if not valid_job_id(name):
                continue
            directory = os.path.join(root, name)
            if not os.path.isdir(directory):
                continue
            state = self._state(name)
            finished = state.get("state") in ("done", "failed")
            submitted_at = float(state.get("submitted_at") or 0)
            if state.get("state") in ("running", "starting") and state.get("worker_pid") and not _pid_alive(state["worker_pid"]):
                self._mark_worker_dead(directory, state)
                finished, state["state"] = True, "failed"
            stale = finished and (now - float(state.get("finished_at") or submitted_at or now)) > job_ttl()
            if stale:
                reaped.append({"job_id": name, "state": state.get("state"),
                               "tool": state.get("tool"), "reason": "ttl_expired"})
                try:
                    shutil.rmtree(directory)
                except OSError as exc:
                    reaped[-1]["cleanup_error"] = str(exc)
                continue
            jobs.append({
                "job_id": name, "state": state.get("state", "unknown"),
                "tool": state.get("tool"),
                "submitted_at": submitted_at or None,
                "finished_at": state.get("finished_at"),
                "worker_pid": state.get("worker_pid"),
                "elapsed_seconds": round(float(state.get("finished_at") or now) - submitted_at, 1) if submitted_at else None,
            })
        return {"jobs": jobs, "count": len(jobs),
                "reaped": reaped, "reaped_count": len(reaped)}

    def remove(self, job_id: str) -> dict:
        directory = self._directory(job_id)
        state = self._state(job_id)
        # A just-spawned worker writes its own PID before accepting work.
        deadline = time.monotonic() + 5
        while state.get("state") == "starting" and not state.get("worker_pid") and time.monotonic() < deadline:
            time.sleep(0.05)
            state = self._state(job_id)
        if state.get("state") == "starting" and not state.get("worker_pid"):
            raise ProviderError("作业尚未确认 worker PID，请稍后重试取消。")
        killed = False
        pid = state.get("worker_pid")
        if state.get("state") in ("running", "starting") and _pid_alive(pid):
            try:
                # The worker first terminates its separate Ghidra/GDB groups.
                os.kill(pid, signal.SIGTERM)
                deadline = time.monotonic() + 10
                while _pid_alive(pid) and time.monotonic() < deadline:
                    time.sleep(0.05)
                if _pid_alive(pid):
                    raise ProviderError("取消尚未确认，保留作业目录；请稍后查询状态。")
                killed = True
            except ProcessLookupError:
                pass
        try:
            shutil.rmtree(directory)
            removed = True
        except OSError as exc:
            removed = False
            raise ProviderError("作业目录清理失败: %s" % exc,
                                limitations=["作业仍然存在，可用 job_list 确认。"]) from exc
        return {"job_id": job_id, "removed": removed, "worker_killed": killed,
                "final_state": state.get("state"),
                "limitations": ["取消不会回滚已经执行的修改；独立调试会话在作业完成后由 gdb_kill 管理。"]}

    # --- 进度提示 ---
    def _log_hint(self, state: dict) -> dict | None:
        """ghidra 作业给出最新进程日志路径，供了解分析进度。"""
        tool = state.get("tool") or ""
        if not tool.startswith("ghidra_"):
            return None
        submitted_at = float(state.get("submitted_at") or 0)
        try:
            logs = sorted(Path(self.workspace).glob("ghidra_logs/*.json"),
                          key=lambda path: path.stat().st_mtime, reverse=True)
        except OSError:
            return None
        for path in logs:
            try:
                if path.stat().st_mtime >= submitted_at - 1:
                    return {"path": str(path),
                            "note": "最新 Ghidra 进程日志，可了解导入/分析进度（不保证属于本作业）。"}
            except OSError:
                continue
        return None


