# -*- coding: utf-8 -*-
"""调试会话的服务进程侧管理。

会话生命周期：
  - 会话是独立的 gdb 进程（由 launch/attach/connect 启动），在工具调用之间、
    MCP 服务重启之间都持续存在；会话状态落盘在 session.json。
由 tools/gdb/main.py 的启动操作创建，见 tools/gdb/gdb_bridge.py 的协议说明。
  - 工具进程（CLI 或 MCP）通过 UNIX socket（control.sock）向 gdb 桥接发送
    JSON 请求；continue 等长操作由调用方超时后发送 SIGINT 中断。
  - 目录结构：$APRE_WORKSPACE/debug_sessions/<session_id>/
      init.json            启动参数（会话创建时写入，只读）
      session.json         会话状态（由 gdb 桥接持续更新）
      control.sock         JSON 行协议控制通道
      gdb.log              gdb 自身 stdout/stderr（含停止通知，供诊断）
      inferior_output.log  被调试进程经 PTY 捕获的完整输出
"""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import signal
import socket
import subprocess
import time
import uuid
from pathlib import Path

from contracts.results import TIMEOUT
from processes import pid_alive as _pid_alive, track_process
from tools.gdb import GDB_BRIDGE_PATH, SESSION_PREFIX
from tools.gdb.probe import gdb_spawn_env, probe_debugger
from tools.gdb.diagnostics import error

SESSIONS_DIRNAME = "debug_sessions"
SOCKET_NAME = "control.sock"
INIT_FILE = "init.json"
STATE_FILE = "session.json"
GDB_LOG = "gdb.log"
OUTPUT_LOG = "inferior_output.log"

VALID_SESSION_ID = set("abcdef0123456789-")


def env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name) or default)
    except ValueError:
        return default
    return value if value > 0 else default


def launch_timeout() -> int:
    return env_int("APRE_DEBUG_LAUNCH_TIMEOUT", 60)


def continue_timeout() -> int:
    return env_int("APRE_DEBUG_CONTINUE_TIMEOUT", 10)


def rpc_timeout() -> int:
    return env_int("APRE_DEBUG_RPC_TIMEOUT", 30)


def idle_timeout() -> int:
    return env_int("APRE_DEBUG_IDLE_TIMEOUT", 3600)


def sessions_root(workspace: str) -> str:
    return os.path.join(os.path.abspath(workspace), SESSIONS_DIRNAME)


def control_socket_path(directory: str, prepare: bool = False) -> str:
    """Linux UNIX socket names are limited to 107 bytes, regardless of PATH_MAX."""
    local = os.path.join(directory, SOCKET_NAME)
    if len(os.fsencode(local)) <= 100:
        return local
    root = Path("/tmp") / ("apre-gdb-%d" % os.getuid())
    if prepare:
        root.mkdir(mode=0o700, exist_ok=True)
        info = root.lstat()
        if root.is_symlink() or not root.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise OSError("调试 socket 目录必须由当前用户独占: %s" % root)
    key = hashlib.sha256(os.fsencode(os.path.abspath(directory))).hexdigest()[:40]
    return str(root / (key + ".sock"))


def valid_session_id(session_id) -> bool:
    return (isinstance(session_id, str) and session_id.startswith(SESSION_PREFIX)
            and len(session_id) > len(SESSION_PREFIX)
            and all(ch in VALID_SESSION_ID for ch in session_id[len(SESSION_PREFIX):]))


def session_dir(workspace: str, session_id: str) -> str:
    if not valid_session_id(session_id):
        raise error("gdb.invalid_session_id", "会话 ID 格式无效: %r" % (session_id,),
                    details={"session_id": session_id},
                    limitations=["没有定位到调试会话，未执行任何调试操作。"])
    path = os.path.join(sessions_root(workspace), session_id)
    if not os.path.isdir(path):
        raise error("gdb.session_not_found", "调试会话不存在: %s" % session_id,
                    status="not_found", details={"session_id": session_id, "path": path},
                    limitations=["会话可能已被终止、清理或从未创建。"],
                    suggestions=["用 gdb_sessions 列出当前会话，必要时用 gdb_launch 重新创建。"])
    return path


def read_session_state(workspace: str, session_id: str) -> dict:
    """读取 session.json；不存在时返回最小化状态（不抛异常）。"""
    try:
        path = os.path.join(session_dir(workspace, session_id), STATE_FILE)
        with open(path, "r", encoding="utf-8") as fh:
            data = json.loads(fh.read())
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"session_id": session_id, "state": "missing"}


def new_session_id() -> str:
    return SESSION_PREFIX + uuid.uuid4().hex


def start_session(workspace: str, init: dict) -> dict:
    """创建会话目录、写入 init.json 并启动 gdb 桥接进程。

    等待初始化完成且控制 socket 就绪（ready=true）或 error 状态后返回；
    启动失败时返回包含 gdb.log 摘要的 ProviderError。
    """
    probe = probe_debugger()
    if not probe["available"]:
        raise error("gdb.gdb_unavailable",
                    "动态调试不可用：%s" % (probe["error"] or "gdb 缺失"),
                    limitations=["没有启动调试会话；目标程序没有被加载或运行。"],
                    details={"probe": {key: probe[key] for key in (
                        "gdb_path", "version", "python_version", "reason")}},
                    suggestions=[probe["install_hint"]])
    gdb = probe["gdb_path"]
    session_id = init.get("session_id") or new_session_id()
    directory = os.path.join(sessions_root(workspace), session_id)
    try:
        os.makedirs(directory, mode=0o700, exist_ok=False)
    except FileExistsError:
        raise error("gdb.session_exists", "会话 ID 冲突: %s" % session_id,
                    details={"session_id": session_id},
                    limitations=["没有覆盖已有会话，未启动新的调试进程。"])
    except OSError as exc:
        raise error("gdb.session_dir_failed", "无法创建会话目录: %s" % exc,
                    details={"directory": directory, "exception_type": type(exc).__name__},
                    limitations=["会话没有建立，目标程序没有被加载或运行。"]) from exc

    init = dict(init)
    if init.get("target"):
        digest = hashlib.sha256()
        with open(init["target"], "rb") as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                digest.update(chunk)
        init["target_sha256"] = digest.hexdigest()
    init["session_id"] = session_id
    init["idle_timeout"] = int(init.get("idle_timeout") or idle_timeout())
    try:
        init["socket_path"] = control_socket_path(directory, prepare=True)
        with open(os.path.join(directory, INIT_FILE), "w", encoding="utf-8") as fh:
            json.dump(init, fh, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        shutil.rmtree(directory, ignore_errors=True)
        raise error("gdb.init_write_failed", "无法写入 init.json: %s" % exc,
                    details={"directory": directory},
                    limitations=["会话初始化没有完成，未启动 gdb。"]) from exc

    env = dict(os.environ)
    env["APRE_SESSION_DIR"] = directory
    env["APRE_GDB_BRIDGE"] = GDB_BRIDGE_PATH
    env = gdb_spawn_env(gdb, env)  # 解包版 gdb 无包装脚本时的库路径兜底
    log_path = os.path.join(directory, GDB_LOG)
    try:
        log_fh = open(log_path, "ab")
    except OSError as exc:
        raise error("gdb.log_open_failed", "无法打开会话日志: %s" % exc,
                    details={"log_path": log_path},
                    limitations=["会话没有启动，目标程序没有被加载或运行。"]) from exc
    try:
        proc = subprocess.Popen(
            [gdb, "-q", "--nx", "-batch", "-x", GDB_BRIDGE_PATH],
            stdin=subprocess.DEVNULL, stdout=log_fh, stderr=subprocess.STDOUT,
            start_new_session=True, env=env,
        )
    except OSError as exc:
        log_fh.close()
        raise error("gdb.gdb_spawn_failed", "gdb 进程启动失败: %s" % exc,
                    details={"gdb_path": gdb, "directory": directory,
                             "exception_type": type(exc).__name__},
                    limitations=["会话没有启动，目标程序没有被加载或运行。"],
                    suggestions=["检查 gdb 可执行权限、动态库依赖与服务进程环境。"]) from exc
    log_fh.close()

    track_process(proc)

    deadline = time.monotonic() + launch_timeout()
    while time.monotonic() < deadline:
        state = read_session_state(workspace, session_id)
        if (state.get("ready") and state.get("state") in ("stopped", "exited", "detached")
                and not state.get("error")):
            return state
        if state.get("state") == "error" or state.get("error"):
            details = {"session_id": session_id, "directory": directory,
                       "gdb_log_path": log_path, "gdb_pid": state.get("gdb_pid"),
                       "snapshot": (state.get("error") or {}).get("snapshot"),
                       "gdb_log_tail": _log_tail(log_path)}
            message = "调试会话初始化失败：%s" % (
                (state.get("error") or {}).get("message") or "见 gdb.log")
            raise error("gdb.session_init_failed", message,
                        limitations=["会话初始化未完成；目标可能未被正确加载、附加或连接。"],
                        details=details,
                        suggestions=["先检查 snapshot 中的 show cwd、info files、info program 和 inferior_output_tail；退出码 127 本身不能证明目标崩溃。",
                                     "完整日志: %s" % log_path])
        if proc.poll() is not None:
            tail = _log_tail(log_path)
            raise error("gdb.gdb_exited_early", "gdb 在会话就绪前退出（退出码 %s）" % proc.returncode,
                        limitations=["会话没有就绪；目标程序没有被调试。"],
                        details={"session_id": session_id, "gdb_log_path": log_path,
                                 "gdb_returncode": proc.returncode, "gdb_log_tail": tail},
                        suggestions=["读取 %s 的完整日志定位桥接脚本或 gdb 启动失败原因。" % log_path])
        time.sleep(0.05)
    raise error("gdb.session_timeout", "等待调试会话就绪超时（>%ss）" % launch_timeout(),
                status=TIMEOUT, details={"session_id": session_id, "directory": directory,
                                         "gdb_log_path": log_path},
                limitations=["会话就绪状态未确认；gdb 进程可能仍在启动，也可能已经失败。"],
                suggestions=["用 gdb_sessions 检查会话状态；若已失败读取 gdb.log 定位原因。"])
    # 使静态检查满意（异常路径总会返回）


def _log_tail(log_path: str, limit: int = 4000) -> str:
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - limit))
            return fh.read()[-limit:]
    except OSError:
        return ""


def rpc(workspace: str, session_id: str, op: str, params: dict | None,
        timeout: int | None = None) -> dict:
    """向会话的 gdb 桥接发送一次 JSON 请求并返回 data；失败抛 ProviderError。"""
    directory = session_dir(workspace, session_id)
    socket_path = control_socket_path(directory)
    timeout = rpc_timeout() if timeout is None else timeout
    deadline = time.monotonic() + timeout
    payload = json.dumps({"id": "rpc-%s" % uuid.uuid4().hex, "op": op,
                          "params": params or {}}, ensure_ascii=False)
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(max(1.0, timeout))
        try:
            sock.connect(socket_path)
        except (OSError, socket.timeout) as exc:
            sock.close()
            state = read_session_state(workspace, session_id)
            raise error("gdb.session_unreachable",
                        "无法连接调试会话 %s: %s" % (session_id, exc),
                        details={"session_id": session_id, "socket_path": socket_path,
                                 "session_state": state.get("state"),
                                 "gdb_pid": state.get("gdb_pid"),
                                 "gdb_log_path": os.path.join(directory, GDB_LOG)},
                        limitations=["调试操作没有送达会话；gdb 可能已退出或正忙。"],
                        suggestions=["用 gdb_sessions 检查会话状态；"
                                     "已结束的会话用 gdb_kill 清理后重新创建。"]) from exc
        try:
            sock.sendall(payload.encode("utf-8") + b"\n")
            buffer = b""
            while b"\n" not in buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("等待响应超时")
                sock.settimeout(remaining)
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buffer += chunk
            if not buffer.strip():
                raise error("gdb.session_closed", "会话连接被对端关闭，没有响应。",
                            limitations=["调试操作没有完成，会话可能已结束。"])
        finally:
            sock.close()
        response = json.loads(buffer.decode("utf-8", "replace"))
        if not isinstance(response, dict):
            raise error("gdb.bad_response", "会话返回了无法解析的响应。",
                        limitations=["调试操作结果不可用，未执行任何后续动作。"])
        if response.get("ok"):
            return response.get("data") or {}
        err = response.get("error") or {}
        raise error(str(err.get("code") or "gdb.operation_failed"),
                    "调试操作 %s 失败：%s" % (op, err.get("message") or "未知错误"),
                    limitations=["操作没有完成；目标进程状态以 gdb_state 为准。"],
                    details={"session_id": session_id, "op": op, "params": params,
                             "exception_type": err.get("exception_type"),
                             "snapshot": err.get("snapshot")},
                    suggestions=["检查地址/表达式是否有效、进程是否仍在运行。"])
    except socket.timeout as exc:
        raise error("gdb.rpc_timeout", "调试会话响应超时（>%ss）: %s" % (timeout, op),
                    status=TIMEOUT, limitations=["操作结果未确认；长操作（continue）可能仍在执行。"],
                    details={"session_id": session_id, "op": op},
                    suggestions=["用 gdb_interrupt 中断运行中的进程，"
                                 "再用 gdb_state 确认状态。"]) from exc


def send_interrupt(workspace: str, session_id: str) -> dict:
    """向会话的 gdb 进程组发送 SIGINT，中断正在运行的目标进程。"""
    state = read_session_state(workspace, session_id)
    pid = state.get("gdb_pid")
    if not isinstance(pid, int) or pid <= 0:
        return {"delivered": False, "reason": "会话没有记录的 gdb PID"}
    if not _gdb_alive(state):
        return {"delivered": False, "reason": "GDB 已退出或 PID 身份不匹配"}
    try:
        os.killpg(pid, signal.SIGINT)
        return {"delivered": True, "gdb_pid": pid}
    except (ProcessLookupError, PermissionError, OSError) as exc:
        return {"delivered": False, "gdb_pid": pid, "reason": str(exc)}


def interrupt_and_wait(workspace: str, session_id: str, wait: float = 15.0) -> dict:
    """SIGINT 后等待会话回到可查询状态，返回 state 结果。"""
    delivered = send_interrupt(workspace, session_id)
    deadline = time.monotonic() + wait
    last_error = None
    while time.monotonic() < deadline:
        try:
            data = rpc(workspace, session_id, "state", {}, timeout=5)
            data["sigint_delivered"] = delivered
            return data
        except Exception as exc:  # 桥接正忙或尚未恢复时重试
            last_error = exc
            time.sleep(0.2)
    raise error("gdb.interrupt_unconfirmed",
                "中断已发送（%s），但会话未在 %ss 内回到可查询状态" % (delivered, wait),
                limitations=["目标进程是否已停止未确认；不要重复盲目发送中断。"],
                details={"session_id": session_id, "delivered": delivered,
                         "last_error": str(last_error)},
                suggestions=["用 gdb_sessions 检查 gdb 进程是否存活。"])


def _process_start(pid):
    try:
        return Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError, TypeError):
        return None


def _gdb_alive(state):
    pid = state.get('gdb_pid')
    if not _pid_alive(pid):
        return False
    expected = state.get('gdb_start_time')
    return expected is None or _process_start(pid) == expected


def list_sessions(workspace: str, reap_exited: bool = False) -> dict:
    """Distinguish debugger liveness, inferior liveness, and operability."""
    root = sessions_root(workspace)
    sessions, reaped = [], []
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        entries = []
    for name in entries:
        directory = os.path.join(root, name)
        if not valid_session_id(name) or not os.path.isdir(directory):
            continue
        state = read_session_state(workspace, name)
        entry = {key: state.get(key) for key in ('mode', 'target', 'gdb_pid', 'inferior_pid',
            'stop', 'exit_code', 'started_at', 'last_activity')}
        entry.update(session_id=name, state=state.get('state', 'unknown'), directory=directory,
            gdb_log_path=os.path.join(directory, GDB_LOG), output_log_path=os.path.join(directory, OUTPUT_LOG),
            gdb_alive=_gdb_alive(state), inferior_alive=None, responsive=False, can_control=False)
        # Backwards-compatible alias; explicitly named fields are authoritative.
        entry['process_alive'] = entry['gdb_alive']
        if entry['state'] == 'missing' and time.time() - os.path.getmtime(directory) < launch_timeout():
            entry['status'] = 'starting'
            sessions.append(entry)
            continue
        ping, ping_error = None, None
        if entry['gdb_alive'] and entry['state'] != 'running':
            try:
                ping = rpc(workspace, name, 'ping', {}, timeout=1)
                if ping.get('gdb_pid') != entry['gdb_pid'] or ping.get('session_id', name) != name:
                    raise ValueError('ping identity mismatch')
                entry['responsive'] = bool(ping.get('pong'))
                entry['state'] = ping.get('state', entry['state'])
                entry['inferior_pid'] = ping.get('inferior_pid', entry['inferior_pid'])
                entry['inferior_alive'] = ping.get('inferior_alive')
            except Exception as exc:
                ping_error = str(exc)
                ping = None
        pid = entry.get('inferior_pid')
        if entry['mode'] != 'remote' and pid:
            live = _pid_alive(pid)
            expected = state.get('inferior_start_time')
            if expected and _process_start(pid) != expected:
                live = False
            entry['inferior_alive'] = live
        if entry['state'] in ('exited', 'closed', 'detached'):
            entry['inferior_alive'] = False
        entry['can_control'] = bool(entry['responsive'] and entry['state'] == 'stopped' and entry['inferior_alive'])
        if entry['state'] == 'exited':
            entry['status'] = 'exited'
        elif entry['state'] in ('closed', 'detached', 'error'):
            entry['status'] = entry['state']
        elif not entry['gdb_alive']:
            entry['status'] = 'dead'
        elif entry['inferior_alive'] is False:
            entry['status'] = 'inferior_unavailable'
        elif entry['state'] in ('starting', 'running'):
            entry['status'] = 'starting' if entry['state'] == 'starting' else 'busy'
        else:
            entry['status'] = 'active' if entry['can_control'] else 'unresponsive'
        if ping_error:
            entry['probe_error'] = ping_error
        terminal = entry['state'] in ('closed', 'detached', 'error')
        should_close = terminal or (reap_exited and entry['state'] == 'exited')
        # Never kill other retained inferiors merely because the selected one exited.
        if should_close and entry['gdb_alive'] and ping and not ping.get('live_inferior_pids', [True]):
            closed = close_session(workspace, name)
            entry['gdb_alive'] = not closed.get('closed', False)
            entry['process_alive'] = entry['gdb_alive']
        if not entry['gdb_alive']:
            summary = {'session_id': name, 'last_state': entry['state'], 'target': entry['target'],
                       'reason': 'terminal_reaped' if should_close else 'gdb_process_dead',
                       'gdb_log_tail': _log_tail(entry['gdb_log_path'])}
            try:
                archive = Path(workspace).resolve() / 'debug_archive'
                archive.mkdir(parents=True, exist_ok=True)
                dest = archive / name
                if dest.exists():
                    dest = archive / (name + '-' + uuid.uuid4().hex[:8])
                try:
                    os.unlink(control_socket_path(directory))
                except FileNotFoundError:
                    pass
                os.replace(directory, str(dest))
                summary.update(archive_path=str(dest), gdb_log_path=str(dest / GDB_LOG),
                               output_log_path=str(dest / OUTPUT_LOG))
            except OSError as exc:
                summary['cleanup_error'] = str(exc)
            reaped.append(summary)
        else:
            if entry['status'] == 'exited':
                entry['action_hint'] = '目标已退出，仅可读输出/日志或关闭；reap_exited=true 可归档回收。'
            sessions.append(entry)
    return {'sessions': sessions, 'count': len(sessions), 'reaped': reaped, 'reaped_count': len(reaped)}


def _socket_alive(socket_path: str) -> bool:
    if not os.path.exists(socket_path):
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            sock.connect(socket_path)
        return True
    except OSError:
        return False


def close_session(workspace: str, session_id: str) -> dict:
    """请求会话正常关闭（结束目标进程并退出 gdb）。socket 不可达时强杀。"""
    state = read_session_state(workspace, session_id)
    data = {"closed": False, "state": state.get("state")}
    if not _gdb_alive(state):
        data["closed"] = True
        return data
    try:
        data.update(rpc(workspace, session_id, "close", {}, timeout=10))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not _gdb_alive(state):
                break
            time.sleep(0.1)
        if _gdb_alive(state):
            os.killpg(state["gdb_pid"], signal.SIGKILL)
            data["force_killed"] = True
    except Exception as exc:
        pid = state.get("gdb_pid")
        if _gdb_alive(state):
            try:
                os.killpg(pid, signal.SIGKILL)
                data["force_killed"] = True
            except OSError as kill_exc:
                data["force_killed"] = False
                data["force_kill_error"] = str(kill_exc)
        data["close_error"] = str(exc)
    data["closed"] = not _gdb_alive(state)
    return data


def cleanup_session_dir(workspace: str, session_id: str) -> bool:
    directory = os.path.join(sessions_root(workspace), session_id)
    if not os.path.isdir(directory):
        return False
    try:
        try:
            os.unlink(control_socket_path(directory))
        except FileNotFoundError:
            pass
        shutil.rmtree(directory)
        return True
    except OSError:
        return False
