"""Ghidra 底层执行器：管理 project 并调用 analyzeHeadless 运行 postScript。

核心职责：
  1. 为每个二进制维护一个独立 project（保留分析/修改状态，便于后续复用）
  2. 首次 import 自动分析，后续 process 复用已分析状态
  3. 调用 analyzeHeadless 执行指定 postScript，捕获并解析结构化输出

输出协议（postScript 端配合）：
  <<<APRE_RESULT_BEGIN>>>
  {json}
  <<<APRE_RESULT_END>>>
  本模块提取 BEGIN/END 之间的 JSON 作为结果。

参数传递：把 Python 端的 args 编码成 JSON 字符串，作为 postScript 的
唯一参数传入（postScript 用 getScriptArgs()[0] 取出再 json.loads）。
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from contracts.results import NOT_FOUND, TIMEOUT
from processes import track_process
from tools.base import ProviderError
from tools.ghidra.config import probe_environment, execution_environment
from tools.ghidra.diagnostics import diagnostic, error, output_warnings, unique, classify_process

# postScript 输出标记
RESULT_BEGIN = "<<<APRE_RESULT_BEGIN>>>"
RESULT_END = "<<<APRE_RESULT_END>>>"

# postScript 所在目录（与本文件同级的 scripts/）
SCRIPTS_DIR = str(Path(__file__).resolve().parent / "scripts")

PROJECT_NAME = "apre"
PROGRAM_NAME = "target"
READY_FILE = ".apre-ready.json"


@dataclass
class Invocation:
    stdout: str
    stderr: str
    stage: str
    log_path: str | None = None
    limitations: list[str] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)

    @property
    def text(self):
        return self.stdout + "\n" + self.stderr

    def details(self):
        return {"stage": self.stage, "log_path": self.log_path,
                "stdout_tail": self.stdout[-4000:], "stderr_tail": self.stderr[-4000:],
                "tails_truncated": len(self.stdout) > 4000 or len(self.stderr) > 4000}


def _project_key(binary_path: str) -> str:
    """根据二进制内容生成 project key，避免不同文件冲突。"""
    h = hashlib.sha256()
    try:
        with open(binary_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError as exc:
        raise error("ghidra.target_read_failed", f"无法读取目标: {binary_path}: {exc}",
                    status=NOT_FOUND if isinstance(exc, FileNotFoundError) else "error",
                    details={"target": binary_path, "exception_type": type(exc).__name__},
                    limitations=["没有读取到目标内容，不能建立内容 hash 或选择分析项目。"]) from exc
    return h.hexdigest()


def _project_dir(workspace: str, binary_path: str) -> str:
    key = _project_key(binary_path)
    return os.path.join(workspace, "ghidra_projects", key)


def _project_ready(project_dir: str) -> bool:
    """Require our import marker, not merely a possibly empty .gpr file."""
    root = Path(project_dir)
    if not (root / (PROJECT_NAME + ".gpr")).is_file():
        return False
    if not (root / (PROJECT_NAME + ".rep")).is_dir():
        return False
    try:
        state = json.loads((root / READY_FILE).read_text(encoding="utf-8"))
        return isinstance(state, dict) and state.get("version") == 1 and state.get("program_name") == PROGRAM_NAME
    except (OSError, ValueError):
        return False


class GhidraRunner:
    """封装 analyzeHeadless 的调用与 project 生命周期。"""

    def __init__(self, workspace: str, timeout: int | None = None):
        self.workspace = os.path.abspath(workspace)
        self.timeout = (int(os.environ.get("APRE_GHIDRA_TIMEOUT") or "600")
                        if timeout is None else timeout)
        if self.timeout <= 0:
            raise ValueError("APRE_GHIDRA_TIMEOUT 必须为正数")
        self._process_env = execution_environment()
        self._startup_environment = probe_environment(self._process_env)
        self._headless = self._startup_environment["headless_path"]
        self._restart_pending = False

    def check_environment(self) -> dict:
        """The same runtime readiness check used before actual execution."""
        current = probe_environment()
        startup = self._startup_environment
        changed = current["environment_fingerprint"] != startup["environment_fingerprint"]
        if (changed or (startup["available"] and not current["available"])
                or self._headless != startup["headless_path"]):
            # Once invalidated, repeated checks cannot clear the restart barrier.
            self._restart_pending = True
        restart = self._restart_pending or (current["available"] and not startup["available"])
        ready = (current["available"] and startup["available"] and not restart
                 and self._headless == current["headless_path"])
        reason = ("environment_unavailable" if not current["available"] else
                  ("provider_restart_required" if not ready else "ready"))
        if current["available"] and not ready:
            current["limitations"].append("当前安装已修复，但旧 Provider 未重新初始化；不能继续分析。")
            current["diagnostics"].append(diagnostic(
                "ghidra.runtime_restart_required", "当前 Provider 运行态需要重建。", severity="error",
                details={"bound_headless": self._headless, "detected_headless": current["headless_path"]}))
        return {
            **current,
            "detected_available": current["available"],
            "available": ready,
            "runtime": {
                "available": ready,
                "initialized_available": startup["available"],
                "restart_required": restart,
                "reason": reason,
                "headless_path": self._headless,
                "detected_headless_path": current["headless_path"],
                "environment_fingerprint": startup["environment_fingerprint"],
                "process_environment": {name: self._process_env.get(name) for name in (
                    "GHIDRA_HOME", "GHIDRA_INSTALL_DIR", "APRE_EXTERNAL_DIR", "JAVA_HOME",
                )},
            },
        }

    def _require_environment(self) -> None:
        state = self.check_environment()
        if state["available"]:
            return
        if state["detected_available"]:
            raise error("ghidra.runtime_restart_required",
                f"Ghidra 安装探测已通过，但当前 APRE 服务（PID {os.getpid()}）的 Provider 运行态未就绪；"
                "请真正重启 APRE MCP 服务进程并重新连接，调用 check_engines 确认 "
                "server_instance_id 已变化、all_available=true 且 can_continue=true。"
                "重复检查或刷新工具列表不能更新当前 Provider。",
                limitations=["没有启动 Ghidra；当前 Provider 绑定的运行态已失效。"],
                details=state["runtime"],
            )
        missing = [dep for dep in state["dependencies"]
                   if not dep["available"] or not dep.get("sufficient", True)]
        detail = ("未找到可执行的 analyzeHeadless" if not state["installed"] else
                  "；".join(f"{dep['name']}: {dep.get('error') or dep.get('reason') or '缺失或版本不满足要求'}"
                            + (f" ({dep['path']}, 权限 {dep.get('permissions')})" if dep.get("path") else "")
                            for dep in missing))
        native_permission = any(dep["name"] == "decompiler" and dep.get("reason") == "not_executable"
                                for dep in missing)
        raise error("ghidra.decompiler_not_executable" if native_permission else "ghidra.environment_unavailable",
            f"Ghidra 当前环境不可用：{detail}。请调用 check_engines 获取安装或修复指引。",
            limitations=["没有启动分析或反编译；缺失或不可执行的依赖必须先修复。"],
            details={"dependencies": missing, "headless_path": state["headless_path"]},
            suggestions=[dep.get("install_hint", "") for dep in missing],
        )

    @contextmanager
    def _lock(self, project_dir: str):
        # Lock files live outside the deletable project, shared by CLI/MCP.
        lock_dir = Path(self.workspace) / "ghidra_projects" / ".locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        with (lock_dir / (Path(project_dir).name + ".lock")).open("a") as fh:
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise error("ghidra.project_lock_timeout", "等待 Ghidra project 锁超时",
                                    status=TIMEOUT, details={"project_dir": project_dir},
                                    limitations=["未获得项目锁，没有开始本次项目操作；可能有其他 APRE 调用正在使用该项目。"])
                    time.sleep(0.05)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    # --- project 管理 ---
    def project_path(self, binary_path: str) -> tuple[str, str]:
        """返回 (project_dir, project_name)。"""
        return _project_dir(self.workspace, binary_path), PROJECT_NAME

    def ensure_project(self, binary_path: str) -> tuple[str, str, bool]:
        """确保 project 就绪。

        返回 (project_dir, project_name, is_new)：
          - 若 project 不存在则首次 import（含自动分析），is_new=True
          - 若已存在则直接复用，is_new=False
        """
        self._require_environment()
        try:
            project_dir, project_name = self.project_path(binary_path)
            with self._lock(project_dir):
                return self._ensure_project(binary_path, project_dir, project_name)
        except OSError as exc:
            raise error("ghidra.project_io_failed", f"建立项目失败: {exc}",
                        details={"target": binary_path},
                        limitations=["项目建立或保存未完成，没有确认可复用的分析状态。"]) from exc

    def _ensure_project(self, binary_path, project_dir, project_name):
        os.makedirs(project_dir, exist_ok=True)

        if _project_ready(project_dir):
            return project_dir, project_name, False
        if (Path(project_dir) / READY_FILE).exists() or (Path(project_dir) / (PROJECT_NAME + ".gpr")).exists():
            raise error("ghidra.project_state_unverified", "已有项目就绪标记无效，无法确认分析状态。",
                        details={"project_dir": project_dir},
                        limitations=["没有覆盖导入已有项目，以免破坏未确认的分析或修改状态。"],
                        suggestions=["检查就绪标记与项目文件权限；先备份，必要时明确重置项目后重新分析。"])

        # Import under a stable name: copies/renames of identical content share
        # the project, and filenames containing spaces or wildcards are safe.
        with tempfile.TemporaryDirectory(prefix="apre-import-") as temp:
            staged = os.path.join(temp, PROGRAM_NAME)
            shutil.copyfile(binary_path, staged)
            if _project_key(staged) != Path(project_dir).name:
                raise ProviderError("目标在导入期间发生变化，请重试")
            stdout = self._invoke([
                self._headless, project_dir, project_name,
                "-import", staged, "-overwrite",
                "-scriptPath", SCRIPTS_DIR, "-postScript", "_dispatch.py",
                json.dumps({"script": "_noop.py", "arguments": {}}, ensure_ascii=True),
            ], timeout=self.timeout)
        result = _extract_result(stdout)
        if "_error" in result:
            raise ProviderError(result["_error"] or "Ghidra script failed without a message", result.get("_status", "error"),
                                data=result.get("_data"),
                                limitations=result.get("_limitations", []) +
                                (stdout.limitations if isinstance(stdout, Invocation) else []),
                                diagnostics=result.get("_diagnostics", []) +
                                (stdout.diagnostics if isinstance(stdout, Invocation) else []))
        if result.get("status") != "imported" or result.get("program_name") != PROGRAM_NAME:
            raise error("ghidra.import_incomplete", f"Ghidra 导入未完成: {result}",
                        details={"project_dir": project_dir},
                        limitations=["未确认目标程序导入完成，不会将项目标记为就绪。"])
        if not (Path(project_dir) / (project_name + ".gpr")).is_file() or not (
            Path(project_dir) / (project_name + ".rep")
        ).is_dir():
            raise error("ghidra.project_not_saved", "Ghidra 导入后未找到持久化 project",
                        details={"project_dir": project_dir},
                        limitations=["未确认分析已保存，不能复用该项目。"])
        diagnostics = result.get("_diagnostics", []) + (
            stdout.diagnostics if isinstance(stdout, Invocation) else [])
        limitations = result.get("_limitations", []) + (
            stdout.limitations if isinstance(stdout, Invocation) else [])
        (Path(project_dir) / READY_FILE).write_text(
            json.dumps({"version": 1, "program_name": PROGRAM_NAME,
                        "analysis_diagnostics": unique(diagnostics),
                        "analysis_limitations": unique(limitations)}), encoding="utf-8",
        )
        return project_dir, project_name, True

    def reset_project(self, binary_path: str) -> dict:
        """删除该二进制对应的 project，下次操作时重新导入分析。"""
        project_dir, _ = self.project_path(binary_path)
        try:
            with self._lock(project_dir):
                from tools.ghidra.worker import ProjectWorker
                ProjectWorker(self, project_dir).stop()
                existed = os.path.isdir(project_dir)
                if existed:
                    shutil.rmtree(project_dir)
        except OSError as exc:
            raise error("ghidra.project_reset_failed", f"重置项目失败: {exc}",
                        details={"project_dir": project_dir, "exception_type": type(exc).__name__},
                        limitations=["删除未完成，项目可能部分删除；不能宣称分析和修改状态已完全清空。"],
                        suggestions=["检查文件权限和正在使用该项目的进程；备份可恢复内容后再处理。"]) from exc
        return {"status": "reset" if existed else "not_present", "target": binary_path,
                "project_path": project_dir}

    # --- 执行 postScript ---
    def run_script(self, binary_path: str, script_name: str,
                   params: dict, read_only: bool = True, *, expected_sha256: str | None = None) -> dict:
        """在已就绪的 project 上运行 postScript，返回解析后的 JSON 结果。

        Args:
          binary_path: 目标二进制路径
          script_name: scripts/ 下的脚本文件名（如 decompile.py）
          params: 传给脚本的参数字典（编码为 JSON 字符串）
          read_only: True 时不修改 program（查询类操作）
        """
        self._require_environment()

        if Path(script_name).name != script_name or not (
            Path(SCRIPTS_DIR) / script_name
        ).is_file():
            raise ProviderError(f"未知 postScript: {script_name}")
        try:
            project_dir, project_name = self.project_path(binary_path)
            if expected_sha256 is not None and Path(project_dir).name != expected_sha256:
                raise error("ghidra.target_changed", "目标文件在内存同步期间变化，未修改工程")
            with self._lock(project_dir):
                _, _, imported = self._ensure_project(binary_path, project_dir, project_name)
                payload = self._run_script(project_dir, project_name, script_name, params, read_only)
                payload.setdefault("_diagnostics", []).append(diagnostic(
                    "ghidra.project", "Ghidra 工程状态", severity="info",
                    details={"project_path": project_dir, "imported_this_call": imported}))
                return payload
        except OSError as exc:
            raise error("ghidra.project_io_failed", f"Ghidra 项目文件操作失败: {exc}",
                        details={"script": script_name, "target": binary_path,
                                 "exception_type": type(exc).__name__},
                        limitations=["项目读写或导入过程未完成；不应把本次失败当成目标没有可分析内容。"],
                        suggestions=["检查目标及 APRE_WORKSPACE 的权限、磁盘空间和完整进程日志。"]) from exc

    def _run_script(self, project_dir, project_name, script_name, params, read_only):
        cmd = [
            self._headless,
            project_dir, project_name,
            "-process", PROGRAM_NAME,
            "-noanalysis",
            "-scriptPath", SCRIPTS_DIR,
            "-postScript", "_dispatch.py",
            json.dumps({"script": script_name, "arguments": params}, ensure_ascii=True),
        ]
        if read_only:
            cmd.append("-readOnly")

        if os.environ.get("APRE_GHIDRA_PERSISTENT", "1") != "0":
            from tools.ghidra.worker import ProjectWorker
            result = ProjectWorker(self, project_dir).run(script_name, params, read_only)
            stdout = None
        else:
            from tools.ghidra.worker import ProjectWorker
            ProjectWorker(self, project_dir).stop()
            stdout = self._invoke(cmd, timeout=self.timeout)
            result = _extract_result(stdout)
        try:
            state = json.loads((Path(project_dir) / READY_FILE).read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                raise ValueError("analysis metadata must be an object")
        except (OSError, ValueError) as metadata_error:
            state = {}
            result.setdefault("_limitations", []).append("分析历史元数据读取失败，当前操作输出保留，但此前分析的完整性无法核实。")
            result.setdefault("_diagnostics", []).append(diagnostic(
                "ghidra.analysis_metadata_unreadable", str(metadata_error),
                details={"metadata_path": str(Path(project_dir) / READY_FILE)}))
        result["_diagnostics"] = unique(result.get("_diagnostics", []) +
            (stdout.diagnostics if isinstance(stdout, Invocation) else []) +
            [{**item, "details": {**item.get("details", {}), "historical": True}}
             for item in state.get("analysis_diagnostics", []) if item.get("severity") != "info"])
        result["_limitations"] = unique(result.get("_limitations", []) +
            (stdout.limitations if isinstance(stdout, Invocation) else []) +
            state.get("analysis_limitations", []))
        # postScript 用 fail() 输出的错误转为 ProviderError
        if "_error" in result:
            raise ProviderError(str(result["_error"] or "Ghidra script failed without a message"), result.get("_status", "error"),
                                data=result.get("_data"), limitations=result["_limitations"],
                                diagnostics=result["_diagnostics"])
        return result

    # --- 底层进程调用 ---
    def _invoke(self, cmd: list[str], timeout: int) -> Invocation:
        self._require_environment()
        stage = "import" if "-import" in cmd else "headless"
        if "-postScript" in cmd and "-import" not in cmd:
            try:
                payload = json.loads(cmd[cmd.index("-postScript") + 2])
                stage = "script:" + payload.get("script", "unknown")
            except (ValueError, IndexError):
                pass
        proc, timed_out = None, False
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace",
                start_new_session=True,
                env=self._process_env,
            )
            track_process(proc)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                # The launcher can spawn a JVM; kill the entire process group.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = proc.communicate()
                report = self._report(cmd, stage, stdout or "", stderr or "", proc.returncode)
                raise ProviderError(
                    f"Ghidra 超时（>{timeout}s），已终止启动器及其进程组。", TIMEOUT,
                    limitations=report.limitations + [
                        "本次操作未完成；若正在导入或修改，项目保存状态未确认，需检查项目而非盲目重试。"],
                    diagnostics=report.diagnostics + [diagnostic(
                        "ghidra.process_timeout", "headless 超时", severity="error",
                        details={**report.details(), "timeout": timeout})],
                )
        except OSError as exc:
            started = proc is not None
            cleanup_error = None
            received_stdout, received_stderr = "", ""
            if started:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError as cleanup:
                    cleanup_error = str(cleanup)
                    try:
                        proc.kill()
                    except OSError:
                        pass
                try:
                    received_stdout, received_stderr = proc.communicate(timeout=2)
                except (OSError, subprocess.TimeoutExpired) as receive:
                    received_stdout = getattr(receive, "output", "")
                    received_stderr = getattr(receive, "stderr", "")
                    cleanup_error = cleanup_error or str(receive)
            describe = lambda value: value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value or "")
            report = self._report(cmd, stage, describe(received_stdout),
                                  str(exc) + "\n" + describe(received_stderr), proc.returncode if started else None)
            code = ("ghidra.timeout_cleanup_failed" if timed_out else
                    "ghidra.process_io_failed" if started else
                    "ghidra.launch_permission_denied" if isinstance(exc, PermissionError) else "ghidra.launch_failed")
            limitation = ("进程已启动，但输出读取或清理失败，执行及保存状态未确认。" if started else
                          "headless 进程没有启动，没有执行本次脚本。")
            if cleanup_error:
                report.limitations.append("进程组清理未确认: " + cleanup_error)
            raise ProviderError(
                f"headless 启动/通信/清理失败 ({cmd[0]}): {exc}", TIMEOUT if timed_out else "error",
                limitations=report.limitations + [limitation],
                diagnostics=report.diagnostics + [diagnostic(
                    code, str(exc), severity="error", details={**report.details(), "launcher": cmd[0],
                    "errno": exc.errno, "started": started, "timeout_triggered": timed_out, "cleanup_error": cleanup_error})],
            ) from exc

        report = self._report(cmd, stage, stdout or "", stderr or "", proc.returncode)
        # A result marker does not prove the modified project was saved.
        if proc.returncode != 0:
            detail = (stderr or stdout or "").strip()[-2000:]
            script_limits, script_diagnostics = [], []
            try:
                script_result = _extract_result(report)
                if "_error" in script_result:
                    detail = str(script_result["_error"])
                    script_limits = script_result.get("_limitations", [])
                    script_diagnostics = script_result.get("_diagnostics", [])
            except ProviderError as parse_failure:
                script_diagnostics = parse_failure.diagnostics
            raise ProviderError(
                f"analyzeHeadless 退出码 {proc.returncode}: {detail}",
                limitations=report.limitations + script_limits + ["headless 异常退出，导入/脚本执行及项目保存均未确认完成。"],
                diagnostics=report.diagnostics + script_diagnostics + [diagnostic(
                    "ghidra.process_failed", "headless 异常退出", severity="error",
                    details={**report.details(), "returncode": proc.returncode})],
            )
        return report

    def _report(self, cmd, stage, stdout, stderr, returncode):
        stdout = stdout.decode("utf-8", "replace") if isinstance(stdout, bytes) else str(stdout or "")
        stderr = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else str(stderr or "")
        diagnostics, limitations = output_warnings(stdout, stderr, stage)
        classified = classify_process(stdout, stderr, stage)
        if classified is not None:
            diagnostics.append(classified)
        report = Invocation(stdout, stderr, stage, diagnostics=diagnostics, limitations=limitations)
        try:
            directory = Path(self.workspace) / "ghidra_logs"
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / (uuid.uuid4().hex + ".json")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as log:
                json.dump({"stage": stage, "command": cmd, "returncode": returncode,
                           "stdout": stdout, "stderr": stderr}, log, ensure_ascii=False)
            report.log_path = str(path)
        except OSError as exc:
            report.limitations.append(f"完整 Ghidra 进程日志未保存: {exc}；诊断仅保留有限长度的输出摘要。")
            report.diagnostics.append(diagnostic("ghidra.log_write_failed", str(exc)))
        report.diagnostics.append(diagnostic(
            "ghidra.invocation", "Ghidra 进程调用记录", severity="info",
            details={"stage": stage, "log_path": report.log_path, "returncode": returncode}))
        return report


def _extract_result(output: str | Invocation) -> dict:
    """从 analyzeHeadless 输出中提取 BEGIN/END 之间的 JSON。"""
    stdout = output.text if isinstance(output, Invocation) else output
    details = output.details() if isinstance(output, Invocation) else {"stdout_tail": stdout[-4000:]}
    def parse_error(code, message, **kwargs):
        exc = error(code, message, **kwargs)
        if isinstance(output, Invocation):
            exc.limitations = unique(output.limitations + exc.limitations)
            exc.diagnostics = unique(output.diagnostics + exc.diagnostics)
            classified = classify_process(output.stdout, output.stderr, output.stage)
            if classified is not None:
                exc.diagnostics = unique(exc.diagnostics + [classified])
                exc.limitations.append("Ghidra reported: " + classified["message"])
        return exc
    matches = re.findall(
        r"^" + re.escape(RESULT_BEGIN) + r"[ \t]*\r?\n(.*?)^"
        + re.escape(RESULT_END) + r"[ \t]*\r?$",
        stdout,
        re.DOTALL | re.MULTILINE,
    )
    if not matches:
        raise parse_error("ghidra.result_missing", "postScript 未输出结构化结果标记。",
                    details=details, limitations=["脚本没有可解析的操作结果，不能确定失败在加载、导入还是脚本执行阶段。"],
                    suggestions=["读取 log_path 的完整 stdout/stderr，检查 loader、Jython 导入和 Java 异常。"])
    if len(matches) != 1:
        raise parse_error("ghidra.multiple_results", "postScript 输出了多个结果，无法确定唯一操作结果",
                    details=details, limitations=["结果有歧义；可能导入了多个程序，当前接口不支持将归档多程序结果合并。"])
    raw_json = matches[0].strip()
    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise parse_error("ghidra.invalid_result_json", f"postScript 输出不是合法 JSON: {exc}",
                    details={**details, "payload_excerpt": raw_json[:500]},
                    limitations=["结果通道损坏，未将截断或不可解析的数据当作分析结果。"]) from exc
    if not isinstance(parsed, dict):
        raise parse_error("ghidra.invalid_result_type", f"postScript 输出不是对象: {type(parsed)}",
                    details=details, limitations=["结果不满足工具协议，无法可靠消费。"])
    return parsed
