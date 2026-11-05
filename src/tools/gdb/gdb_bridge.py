# -*- coding: utf-8 -*-
"""APRE 动态调试桥接脚本：在 gdb 进程内运行的 Python 服务。

职责：
  - 读取 APRE_SESSION_DIR 下的 init.json，加载/运行/附加/连接目标
  - 通过 PTY 提供 inferior 的交互式输入输出（行缓冲、可写 stdin）
  - 绑定 UNIX socket（control.sock），以逐行 JSON 协议服务外部工具调用
  - 维护 session.json 中的会话状态（starting/stopped/running/exited/detached/closed/error）
  - 空闲超时自动结束会话；收到 SIGINT 时中断运行中的 inferior

运行方式（由 tools/gdb/session.py 启动）：
    gdb -q --nx -batch -x <本文件>
    环境变量 APRE_SESSION_DIR 指向会话目录。

注意：本脚本运行在 gdb 内嵌 Python 中，必须兼容 Python 3.6+（不使用
f-string），且只依赖标准库与 gdb 模块。
"""

import fcntl
import hashlib
import codecs
import gdb
import json
import os
import re
import select
import shlex
import signal
import socket
import sys
import threading
import time
import traceback

SESSION_DIR = os.environ.get("APRE_SESSION_DIR", "")
SOCKET_NAME = "control.sock"
STATE_FILE = "session.json"
OUTPUT_LOG = "inferior_output.log"
INIT_FILE = "init.json"
MAX_REQUEST_BYTES = 1 << 20
MAX_OUTPUT_BYTES = 1 << 20  # 单次返回的最大输出量，超出部分留在下次读取

_ctx = {
    "state": "starting",
    "stop": None,
    "exit_code": None,
    "error": None,
    "session_id": "",
    "socket_path": os.path.join(SESSION_DIR, SOCKET_NAME),
    "mode": "",
    "target": None,
    "target_sha256": None,
    "stop_at": None,
    "effective_stop_at": None,
    "ready": False,
    "init_watchdog_fired": False,
    "started_at": time.time(),
    "last_activity": time.time(),
    "pty_master": None,
    "output_log_fd": None,
    "output_read_offset": 0,
    "pending_read_offset": 0,
    "pending_truncated": False,
    "warnings": [],
    "startup_warnings": [],
    "last_command": None,
    "fatal": False,
}
_pty_lock = threading.RLock()
_pty_done = threading.Event()


def log(msg):
    try:
        sys.stderr.write("[apre-bridge] %s\n" % msg)
        sys.stderr.flush()
    except Exception:
        pass


def _json_default(value):
    return str(value)


def write_session(extra=None):
    """把当前会话状态写入 session.json（每次调用都重建文件内容）。"""
    if not SESSION_DIR:
        return
    try:
        selected_pid = int(gdb.selected_inferior().pid)
        if selected_pid:
            _ctx['inferior_pid'] = selected_pid
            _ctx['inferior_start_time'] = _proc_start(selected_pid) if _ctx['mode'] != 'remote' else None
    except Exception:
        pass
    data = {
        "gdb_start_time": _proc_start(os.getpid()),
        "inferior_pid": _ctx.get('inferior_pid'),
        "inferior_start_time": _ctx.get('inferior_start_time'),
        "version": 1,
        "session_id": _ctx["session_id"],
        "gdb_pid": os.getpid(),
        "socket_path": _ctx["socket_path"],
        "mode": _ctx["mode"],
        "target": _ctx["target"],
        "target_sha256": _ctx["target_sha256"],
        "stop_at": _ctx["stop_at"],
        "effective_stop_at": _ctx["effective_stop_at"],
        "ready": _ctx["ready"],
        "state": _ctx["state"],
        "stop": _ctx["stop"],
        "exit_code": _ctx["exit_code"],
        "error": _ctx["error"],
        "warnings": _ctx["warnings"],
        "startup_warnings": _ctx["startup_warnings"],
        "started_at": _ctx["started_at"],
        "last_activity": _ctx["last_activity"],
    }
    if extra:
        data.update(extra)
    path = os.path.join(SESSION_DIR, STATE_FILE)
    temp = path + ".tmp"
    try:
        with open(temp, "w") as fh:
            json.dump(data, fh, ensure_ascii=True, default=_json_default)
        os.replace(temp, path)
    except (OSError, ValueError) as exc:
        log("write session.json failed: %s" % exc)


def set_state(state, **extra):
    _ctx["state"] = state
    _ctx["last_activity"] = time.time()
    write_session(extra)
    log("state -> %s%s" % (state, (" %s" % extra) if extra else ""))


# ── inferior 输出捕获（PTY） ─────────────────────────────────────────

def pty_setup():
    """为 inferior 分配 PTY：行缓冲输出 + 可交互 stdin。"""
    master, slave = os.openpty()
    name = os.ttyname(slave)
    flags = fcntl.fcntl(master, fcntl.F_GETFL)
    fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    gdb.execute("set inferior-tty %s" % name, to_string=True)
    os.close(slave)
    _ctx["pty_master"] = master
    _ctx["output_log_fd"] = os.open(os.path.join(SESSION_DIR, OUTPUT_LOG),
                                    os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)

    def collect_output():
        # No GDB API calls on this thread. Draining while gdb.execute blocks
        # prevents verbose programs from blocking on a full terminal buffer.
        while not _pty_done.is_set():
            try:
                readable, _, _ = select.select([master], [], [], 0.1)
                if readable and not drain_pty():
                    _pty_done.wait(0.02)  # No inferior has opened the slave yet.
            except OSError as exc:
                _ctx["warnings"].append("目标输出归档失败: %s" % exc)
                return

    threading.Thread(target=collect_output, daemon=True).start()
    log("inferior pty: %s" % name)


def pty_write(data):
    if _ctx["pty_master"] is None:
        raise RuntimeError("inferior 没有可写入的终端")
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return os.write(_ctx["pty_master"], data)


def _append_output(chunk):
    if not chunk:
        return
    while chunk:
        written = os.write(_ctx["output_log_fd"], chunk)
        chunk = chunk[written:]


def drain_pty():
    """把 PTY 中积累的输出读出来并归档；每次只能读到缓冲区上限。"""
    with _pty_lock:
        return _drain_pty()


def _drain_pty():
    if _ctx["pty_master"] is None:
        return b""
    drained = []
    for _ in range(64):
        try:
            data = os.read(_ctx["pty_master"], 65536)
        except OSError:
            data = b""
        if not data:
            break
        drained.append(data)
    if not drained:
        return b""
    chunk = b"".join(drained).replace(b"\r\n", b"\n")
    _append_output(chunk)
    return chunk


def _read_output(cursor):
    with open(os.path.join(SESSION_DIR, OUTPUT_LOG), "rb") as stream:
        stream.seek(_ctx[cursor])
        chunk = stream.read(MAX_OUTPUT_BYTES)
        more = stream.tell() < os.fstat(stream.fileno()).st_size
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        text = decoder.decode(chunk, final=not more)
        # Keep a UTF-8 character split by the page boundary for the next call.
        _ctx[cursor] = stream.tell() - len(decoder.getstate()[0])
    return {"output": text, "truncated": more}


def take_pending_output():
    result = _read_output("pending_read_offset")
    _ctx["pending_truncated"] = result["truncated"]
    return result["output"]


# ── 停止/退出事件 ───────────────────────────────────────────────────

def on_stop(event):
    info = {"reason": "stopped", "event": type(event).__name__}
    # Some GDB versions emit a plain StopEvent even for an inferior int3.
    # Preserve MI evidence; do not infer a signal from the instruction bytes.
    details = getattr(event, 'details', {})
    info['details'] = {str(key): str(value) for key, value in details.items()}
    if details.get('reason') == 'end-stepping-range':
        info['reason'] = 'step'
    elif details.get('reason') == 'signal-received':
        info['reason'] = 'signal'
        info['signal'] = details.get('signal-name')
    if isinstance(event, gdb.BreakpointEvent):
        info["reason"] = "breakpoint"
        info["bp_numbers"] = [int(bp.number) for bp in event.breakpoints]
        try:
            info["bp_number"] = int(event.breakpoint.number)
            info["bp_location"] = str(event.breakpoint.location)
        except Exception:
            pass
    elif isinstance(event, gdb.SignalEvent):
        info["reason"] = "signal"
        try:
            info["signal"] = str(event.stop_signal)
        except Exception:
            pass
    try:
        frame = gdb.newest_frame()
        info["pc"] = hex(int(frame.pc()))
        info["function"] = frame.name()
    except Exception:
        pass
    try:
        thread = gdb.selected_thread()
        if thread is not None:
            info["thread_id"] = int(thread.num)
    except Exception:
        pass
    _ctx["stop"] = info
    _ctx["exit_code"] = None
    _ctx["state"] = "stopped"
    drain_pty()
    write_session()


def on_exit(event):
    if _ctx.get("fatal"):
        # 初始化失败后 gdb 退出会再触发 exited 事件；不要覆盖已记录的错误状态。
        return
    try:
        _ctx["exit_code"] = int(event.exit_code)
    except Exception:
        _ctx["exit_code"] = None
    _ctx["stop"] = None
    _ctx["state"] = "exited"
    drain_pty()
    write_session()
    log("inferior exited: %s" % _ctx["exit_code"])


gdb.events.stop.connect(on_stop)
gdb.events.exited.connect(on_exit)


# ── 地址/状态辅助 ───────────────────────────────────────────────────

def parse_addr(text):
    """接受 0x 前缀十六进制或十进制字符串。"""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("地址不能为空")
    text = text.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    try:
        return int(text, 10)
    except ValueError:
        return int(text, 16)


def resolve_addr(text):
    """把地址参数解析为整数：先按数字解析，失败时按 gdb 表达式求值（如 $rsp、main+8）。"""
    try:
        return parse_addr(text)
    except ValueError:
        pass
    value = gdb.parse_and_eval(text)
    if value.type.strip_typedefs().code == gdb.TYPE_CODE_ARRAY:
        return int(value.address)
    return int(value)


def current_pc():
    frame = gdb.newest_frame()
    return int(frame.pc())


def inferior_alive():
    try:
        return gdb.selected_inferior().pid != 0
    except Exception:
        return False


def inferior_threads():
    out = gdb.execute("info threads", to_string=True)
    threads = []
    pattern = re.compile(
        r"^\s*(\*?)\s*(\d+)\s+Thread\s+(0x[0-9a-fA-F]+)\s+\(LWP\s+(\d+)\)"
        r"(?:\s+\"([^\"]*)\")?\s*(.*)$")
    for line in out.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        threads.append({
            "id": int(match.group(2)),
            "selected": bool(match.group(1)),
            "target_id": match.group(3),
            "lwp": int(match.group(4)),
            "name": match.group(5) or "",
            "frame": match.group(6).strip(),
        })
    return threads


def state_summary():
    data = {"state": _ctx["state"], "stop": _ctx["stop"], "exit_code": _ctx["exit_code"]}
    data["effective_stop_at"] = _ctx["effective_stop_at"]
    data["warnings"] = list(_ctx["warnings"])
    try:
        if inferior_alive():
            data["pid"] = gdb.selected_inferior().pid
            data["pc"] = hex(current_pc())
            frame = gdb.newest_frame()
            try:
                data["function"] = frame.name()
            except Exception:
                data["function"] = None
            try:
                thread = gdb.selected_thread()
                data["thread_id"] = int(thread.num) if thread is not None else None
            except Exception:
                pass
    except Exception:
        pass
    try:
        data["threads"] = inferior_threads()
    except Exception:
        pass
    return data


# ── 会话初始化 ──────────────────────────────────────────────────────

def _init_watchdog_seconds():
    try:
        value = int(os.environ.get("APRE_DEBUG_INIT_WATCHDOG", "10") or "10")
        return value if value > 0 else 10
    except ValueError:
        return 10


def _bounded_execute(command, label):
    """执行可能长时间不返回的 gdb 命令；超时后向本进程组发 SIGINT 中断。

    用于会话初始化阶段的 run/continue/attach/target remote：一旦目标
    跑飞（入口换算错误、程序阻塞等待输入等），初始化看门狗会打断执行，
    保证控制 socket 一定能建立，会话不会死在 init 阶段。
    """
    stopped = threading.Event()
    fired = threading.Event()
    _ctx["init_watchdog_fired"] = False
    seconds = _init_watchdog_seconds()

    def watchdog():
        if not stopped.wait(seconds):
            fired.set()
            log("init watchdog fired for %s; sending SIGINT" % label)
            try:
                os.killpg(os.getpgrp(), signal.SIGINT)
            except OSError as exc:
                log("watchdog killpg failed: %s" % exc)

    thread = threading.Thread(target=watchdog, daemon=True)
    thread.start()
    try:
        _ctx["last_command"] = command
        # Keep native diagnostics even if execute raises before returning output.
        gdb.execute(command, to_string=False)
    except KeyboardInterrupt:
        log("%s interrupted by init watchdog" % label)
    finally:
        stopped.set()
        thread.join()
        _ctx["init_watchdog_fired"] = fired.is_set()
        if fired.is_set():
            _ctx["warnings"].append(
                "初始化命令 %s 超过 %ss，看门狗已发送 SIGINT；"
                "请核对实际停止状态，必要时用 gdb_continue 恢复执行。" % (label, seconds))


def _watchdog_interrupted():
    """当前停止是否由初始化看门狗的 SIGINT 造成。"""
    return _ctx["init_watchdog_fired"]


def init_session():
    init = {}
    path = os.path.join(SESSION_DIR, INIT_FILE)
    with open(path, "r") as fh:
        init = json.loads(fh.read())
    _ctx["session_id"] = init.get("session_id", "")
    _ctx["socket_path"] = init.get("socket_path") or os.path.join(SESSION_DIR, SOCKET_NAME)
    _ctx["mode"] = init.get("mode", "launch")
    _ctx["target"] = init.get("target")
    _ctx["target_sha256"] = init.get("target_sha256")
    _ctx["stop_at"] = init.get("stop_at", "entry")

    gdb.execute("set pagination off", to_string=True)
    gdb.execute("set confirm off", to_string=True)
    gdb.execute("set breakpoint pending on", to_string=True)
    pty_setup()

    if _ctx["mode"] == "attach":
        pid = int(init.get("pid", 0))
        if init.get("target"):
            gdb.execute("file %s" % _quote_filename(init["target"]), to_string=True)
        _bounded_execute("attach %d" % pid, "attach")
        set_state("stopped")
        log("attached to pid %d" % pid)
        return

    if _ctx["mode"] == "remote":
        if init.get("target"):
            gdb.execute("file %s" % _quote_filename(init["target"]), to_string=True)
        _bounded_execute("target remote %s:%s" % (init.get("host"), init.get("port")),
                         "target remote")
        set_state("stopped")
        log("connected to %s:%s" % (init.get("host"), init.get("port")))
        return

    # This explicit policy controls delivery; it does not cancel kernel timers.
    alarm_policy = init.get('alarm_policy', 'default')
    if alarm_policy not in ('default', 'stop', 'ignore'):
        raise ValueError('invalid alarm_policy')
    if alarm_policy != 'default':
        gdb.execute('handle SIGALRM ' + ('stop print pass' if alarm_policy == 'stop' else 'nostop noprint nopass'), to_string=True)

    # mode == launch
    target = init["target"]
    gdb.execute("file %s" % _quote_filename(target), to_string=True)
    args = init.get("args") or []
    if args:
        gdb.execute("set args %s" % " ".join(shlex.quote(a) for a in args),
                    to_string=True)
    for key, value in (init.get("env") or {}).items():
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key) or any(c in str(value) for c in "\x00\r\n"):
            raise ValueError("env 名称必须为环境变量标识符，值不能包含换行或 NUL")
        gdb.execute("set environment %s %s" % (key, value), to_string=True)
    cwd = init.get("cwd")
    if cwd:
        if any(c in cwd for c in "\x00\r\n"):
            raise ValueError("cwd 不能包含换行或 NUL")
        cwd = os.path.abspath(cwd)
        if not os.path.isdir(cwd):
            raise ValueError("cwd 不存在或不是目录: %s" % cwd)
        # Unlike `file`, `set cwd` treats quotes as literal filename characters.
        gdb.execute("set cwd %s" % cwd, to_string=True)
        actual = gdb.parameter("cwd")
        if actual != cwd:
            raise RuntimeError("cwd 设置未生效: requested=%r actual=%r" % (cwd, actual))
    stop_at = init.get("stop_at", "entry")
    if stop_at == "entry":
        _stop_at_program_entry()
    elif stop_at == "main":
        _stop_at_main()
    elif stop_at == "input":
        _stop_at_input()
    else:  # none
        _ctx["effective_stop_at"] = "none"
        _bounded_execute("run", "run")
    drain_pty()
    if _ctx["state"] == "running":
        set_state("stopped")
    log("launch init done, state=%s" % _ctx["state"])
    write_session()


def _stop_at_input():
    """Stop before a Linux stdin read/readv; do not infer blocking from SIGINT."""
    _stop_at_program_entry()
    if _ctx["state"] != "stopped" or _watchdog_interrupted():
        return
    arch = gdb.selected_frame().architecture().name()
    if "x86-64" in arch:
        fd = "$rdi"
    elif arch.startswith("i386"):
        fd = "$ebx"
    elif "aarch64" in arch:
        fd = "$x0"
    else:
        raise RuntimeError("stop_at=input 暂不支持架构 %s；请用 entry 后 send_input/continue" % arch)
    before = set(bp.number for bp in (gdb.breakpoints() or []))
    created = []
    try:
        gdb.execute("catch syscall read readv", to_string=True)
        created = [bp for bp in (gdb.breakpoints() or []) if bp.number not in before]
        if not created:
            raise RuntimeError("GDB 未建立 stdin syscall catchpoint")
        for bp in created:
            bp.condition = "%s == 0" % fd
        _ctx["effective_stop_at"] = None
        _bounded_execute("continue", "stdin read")
        stop = _ctx.get("stop") or {}
        if not _watchdog_interrupted() and any(bp.number in stop.get("bp_numbers", []) for bp in created):
            stop["reason"] = "input_request"
            stop["input_fd"] = 0
            _ctx["effective_stop_at"] = "input"
    finally:
        for bp in created:
            if bp.is_valid():
                bp.delete()


def failure_snapshot():
    """Best-effort evidence, including startup failures with no live inferior."""
    snapshot = {"state": _ctx["state"], "stop": _ctx["stop"],
                "exit_code": _ctx["exit_code"], "target": _ctx["target"],
                "last_command": _ctx["last_command"]}
    for command in ("show cwd", "show args", "show inferior-tty", "info files",
                    "info program", "info inferiors", "info threads", "bt 8"):
        try:
            snapshot[command] = gdb.execute(command, to_string=True)[-6000:]
        except Exception as exc:
            snapshot[command] = {"unavailable": str(exc)}
    try:
        drain_pty()
        with open(os.path.join(SESSION_DIR, OUTPUT_LOG), "rb") as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 4000))
            snapshot["inferior_output_tail"] = stream.read().decode("utf-8", "replace")
    except Exception as exc:
        snapshot["output_error"] = str(exc)
    try:
        with open(os.path.join(SESSION_DIR, "gdb.log"), "rb") as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 6000))
            snapshot["gdb_output_tail"] = stream.read().decode("utf-8", "replace")
    except Exception:
        pass
    log("failure snapshot: %s" % json.dumps(snapshot, ensure_ascii=True))
    return snapshot


def _stop_at_main():
    """先确认 main 断点可解析，再运行；pending 断点不能作为成功依据。"""
    breakpoint = None
    unresolved = None
    try:
        breakpoint = gdb.Breakpoint("main", temporary=True, internal=True)
        if breakpoint.pending:
            unresolved = "main 断点未解析（pending）"
    except gdb.error as exc:
        unresolved = str(exc)
    if unresolved is not None:
        if breakpoint is not None and breakpoint.is_valid():
            breakpoint.delete()
        _ctx["warnings"].append(
            "无法解析 main 符号（%s），stop_at=main 退回程序入口；"
            "未推断 stripped 程序的 main 地址。" % unresolved)
        _stop_at_program_entry()
        return

    number = int(breakpoint.number)
    try:
        _bounded_execute("run", "main run")
        stop = _ctx.get("stop") or {}
        if (stop.get("reason") == "breakpoint" and
                number in stop.get("bp_numbers", []) and not _watchdog_interrupted()):
            _ctx["effective_stop_at"] = "main"
        else:
            _ctx["warnings"].append(
                "stop_at=main 未命中 main 断点，实际 state=%s，stop=%s；"
                "保留当前状态，未重新运行目标。" % (_ctx["state"], stop))
    finally:
        if breakpoint.is_valid():
            breakpoint.delete()


def _stop_at_program_entry():
    """停在程序入口：先 starti 到首条指令，再继续到重定位后的入口。

    非 PIE 程序 starti 已经停在程序入口，直接返回（此前对同一地址再
    tbreak+continue 会导致断点永不命中、inferior 跑飞阻塞初始化）。
    """
    _bounded_execute("starti", "starti")
    if _watchdog_interrupted() or _ctx["state"] != "stopped":
        _ctx["warnings"].append("starti 未确认首条指令停点，保留当前状态。")
        return
    target = _relocated_program_entry()
    if target is None:
        _ctx["warnings"].append("未解析到程序入口，保留首条指令停点（ld.so 入口）。")
        _ctx["effective_stop_at"] = "instruction"
        return
    try:
        if current_pc() == target:
            _ctx["effective_stop_at"] = "entry"
            log("starti already at program entry %s" % hex(target))
            return
        gdb.execute("tbreak *%s" % hex(target), to_string=True)
        _bounded_execute("continue", "entry continue")
        if _ctx.get("state") == "stopped":
            stop_pc = (_ctx.get("stop") or {}).get("pc")
            if _watchdog_interrupted() or (stop_pc and int(stop_pc, 16) != target):
                _ctx["warnings"].append(
                    "未停在换算后的程序入口（%s），当前停点: %s；会话可用，"
                    "可用 gdb_state 核对实际停点。" % (hex(target), stop_pc or "未知"))
            elif stop_pc and int(stop_pc, 16) == target:
                _ctx["effective_stop_at"] = "entry"
        else:
            _ctx["warnings"].append("目标在到达程序入口前结束，未确认入口停点。")
    except Exception as exc:
        _ctx["warnings"].append("无法停在重定位后的程序入口（%s），保留当前状态。" % exc)
        log("relocated entry stop failed: %s" % exc)


def _relocated_program_entry():
    """计算重定位后的程序入口地址；无法计算时返回 None。

    PIE 的 e_entry 是小偏移（通常 <0x100000），需要加上运行时基址；
    非 PIE 的入口是绝对地址，直接使用。
    """
    entry = _find_entry_point()
    if entry is None:
        return None
    if entry >= 0x100000:
        return entry
    try:
        out = gdb.execute("info proc mappings", to_string=True)
        pattern = re.compile(r"^(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+"
                             r"0x0+\s+\S+\s+(.+?)\s*$")
        for line in out.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            objfile = match.group(2).strip()
            if objfile == _ctx["target"] or objfile == os.path.realpath(_ctx["target"]):
                return int(match.group(1), 16) + entry
    except Exception:
        pass
    return None


def _quote_filename(path):
    if any(c in path for c in "\x00\r\n"):
        raise ValueError("文件路径不能包含换行或 NUL")
    return '"%s"' % path.replace("\\", "\\\\").replace('"', '\\"')


def _find_entry_point():
    try:
        out = gdb.execute("info files", to_string=True)
        match = re.search(r"Entry point:\s+(0x[0-9a-fA-F]+)", out)
        return int(match.group(1), 16) if match else None
    except Exception:
        return None


# ── 操作实现 ────────────────────────────────────────────────────────

def run_inferior(kind):
    """执行 continue/step 类命令，返回停止后的状态摘要。"""
    if _ctx["state"] == "exited" or not inferior_alive():
        raise RuntimeError("没有正在运行的目标进程（未启动或已退出）")
    _ctx["stop"] = None
    _ctx["exit_code"] = None
    set_state("running")
    commands = {
        "continue": "continue",
        "step_instruction": "stepi",
        "next_instruction": "nexti",
        "step_line": "step",
        "next_line": "next",
        "finish": "finish",
    }
    try:
        _ctx["last_command"] = commands[kind]
        gdb.execute(commands[kind], to_string=False)
    except KeyboardInterrupt:
        log("interrupted during %s" % kind)
    except Exception as exc:
        drain_pty()
        if _ctx["state"] == "running":
            set_state("stopped")
        raise
    drain_pty()
    if _ctx["state"] == "running":
        set_state("stopped")
    data = state_summary()
    data["output"] = take_pending_output()
    data["output_truncated"] = _ctx["pending_truncated"]
    return data


def op_continue(params):
    return run_inferior("continue")


def op_step(params):
    action = params.get("action", "step_instruction")
    if action == "run_until":
        address = params.get("address")
        if not address:
            raise ValueError("run_until 需要 address 参数")
        if not inferior_alive():
            raise RuntimeError("没有正在运行的目标进程（未启动或已退出）")
        gdb.execute("tbreak *%s" % address, to_string=True)
        return run_inferior("continue")
    return run_inferior(action)


def op_trace(params):
    if _ctx['state'] != 'stopped':
        raise RuntimeError('跟踪要求目标处于 stopped 状态')
    action = params.get('action', 'step_instruction')
    count, seconds = int(params.get('max_steps', 100)), int(params.get('timeout', 10))
    if action not in ('step_instruction', 'next_instruction', 'continue') or not 1 <= count <= 10000 or not 1 <= seconds <= 300:
        raise ValueError('无效的跟踪模式或上限')
    memory_length = int(params.get('memory_length', 0))
    if bool(params.get('memory_address')) != bool(memory_length) or not 0 <= memory_length <= 4096:
        raise ValueError('无效的内存采集范围')
    directory = params['artifact_dir']
    path = os.path.join(directory, 'trace.jsonl')
    done, expired = threading.Event(), threading.Event()
    def watchdog():
        if not done.wait(seconds):
            expired.set()
            os.killpg(os.getpgrp(), signal.SIGINT)
    timer = threading.Thread(target=watchdog, daemon=True)
    completed, preview, termination, failure = 0, [], 'max_steps', None
    deadline = time.monotonic() + seconds
    # Open before executing anything. A failed file creation cannot advance the inferior.
    with open(path, 'x') as stream:
        timer.start()
        try:
            for index in range(count):
                if expired.is_set() or time.monotonic() >= deadline:
                    termination = 'timeout'
                    break
                state = run_inferior(action)
                row = {'index': index, 'state': state.get('state'), 'stop': state.get('stop'),
                       'exit_code': state.get('exit_code')}
                output = state.get('output', '')
                row['output'] = output[:4096]
                row['output_truncated'] = len(output) > 4096 or state.get('output_truncated', False)
                if _ctx['state'] == 'stopped':
                    if params.get('registers'):
                        row['registers'] = op_registers({'names': params['registers']})['registers']
                    if memory_length:
                        try:
                            address = resolve_addr(params['memory_address'])
                            raw = bytes(gdb.selected_inferior().read_memory(address, memory_length))
                            if len(raw) != memory_length:
                                raise RuntimeError('short memory read')
                            memory_path = os.path.join(directory, '%06d.bin' % index)
                            with open(memory_path, 'xb') as memory_file:
                                memory_file.write(raw)
                            row['memory'] = {'address': hex(address), 'length': len(raw), 'path': memory_path,
                                             'sha256': hashlib.sha256(raw).hexdigest()}
                        except Exception as exc:
                            row['memory_error'] = str(exc)
                stream.write(json.dumps(row, ensure_ascii=True) + '\n')
                stream.flush()
                completed += 1
                if len(preview) < 3:
                    preview.append(row)
                stop = row.get('stop') or {}
                if expired.is_set():
                    termination = 'timeout'
                    break
                if row['state'] != 'stopped':
                    termination = row['state'] or 'not_stopped'
                    break
                if row.get('memory_error') or any(r.get('error') for r in row.get('registers', [])):
                    termination, failure = 'error', '停止点数据采集失败；详见 JSONL'
                    break
                if stop.get('reason') == 'signal' and stop.get('signal') not in params.get('continue_signals', []):
                    termination = 'signal'
                    break
                if stop.get('reason') == 'breakpoint' and not params.get('continue_breakpoints', False):
                    termination = 'breakpoint'
                    break
                if stop.get('reason') not in ('signal', 'breakpoint', 'step') and not params.get('continue_unknown_stops', False):
                    termination = 'unknown_stop'
                    break
        except KeyboardInterrupt:
            termination = 'timeout' if expired.is_set() else 'interrupted'
        except Exception as exc:
            termination, failure = 'error', str(exc)
        finally:
            done.set()
            timer.join()
    return {'path': path, 'format': 'jsonl', 'records': completed, 'max_steps': count,
            'termination': termination, 'error': failure, 'preview': preview,
            'state': state_summary()}


def op_state(params):
    drain_pty()
    data = state_summary()
    data["output"] = take_pending_output()
    data["output_truncated"] = _ctx["pending_truncated"]
    return data


def op_output(params):
    drain_pty()
    return _read_output("output_read_offset")


def op_input(params):
    data = params.get("data")
    if not isinstance(data, str) or not data:
        raise ValueError("data 必须是非空字符串")
    if not inferior_alive():
        raise RuntimeError("目标进程没有运行（输入只能写给运行中的进程）")
    written = pty_write(data)
    return {"written": written, "requested": len(data.encode("utf-8", "replace")),
            "complete": written == len(data.encode("utf-8", "replace")),
            "buffered": "输入已写入终端缓冲区，由程序在恢复执行后读取。"}


def op_registers(params):
    if not inferior_alive():
        raise RuntimeError("目标进程没有运行（寄存器不可读）")
    names = list(params.get("names") or [])
    registers = []
    if names:
        for name in names:
            entry = {"name": name}
            try:
                value = gdb.parse_and_eval("$%s" % name)
                entry.update(_value_fields(value))
            except Exception as exc:
                entry["error"] = str(exc)
            registers.append(entry)
    else:
        command = "info all-registers" if params.get("all") else "info registers"
        text = gdb.execute(command, to_string=True)
        parsed = _parse_registers_text(text)
        for name in parsed:
            entry = {"name": name, "raw": parsed[name]}
            try:
                value = gdb.parse_and_eval("$%s" % name)
                entry.update(_value_fields(value))
            except Exception:
                pass
            registers.append(entry)
    return {"registers": registers, "count": len(registers)}


def _parse_registers_text(text):
    """解析 info registers / info all-registers 的多行输出。"""
    result = {}
    current = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            parts = line.split(None, 1)
            name = parts[0]
            if re.match(r"^[A-Za-z0-9_$]+$", name):
                current = name
                result[name] = parts[1] if len(parts) > 1 else ""
                continue
        if current is not None and line.strip():
            result[current] = result[current] + " " + line.strip()
    return result


def _value_fields(value):
    fields = {"value": str(value)}
    try:
        fields["type"] = str(value.type)
    except Exception:
        pass
    try:
        fields["int"] = int(value)
        fields["hex"] = hex(fields["int"])
    except Exception:
        pass
    return fields


def _proc_status(pid):
    with open('/proc/%d/status' % pid) as stream:
        return dict(line.split(':', 1) for line in stream if ':' in line)


def _proc_start(pid):
    try:
        with open('/proc/%d/stat' % pid) as stream:
            return stream.read().rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def op_tracee_read(params):
    if not sys.platform.startswith('linux') or _ctx['mode'] == 'remote':
        raise RuntimeError('tracee_read 仅支持本地 Linux 会话')
    if _ctx['state'] != 'stopped' or not inferior_alive():
        raise RuntimeError('tracer inferior 必须处于 stopped 状态')
    pid, length = int(params['pid']), int(params['length'])
    if pid <= 0 or not 1 <= length <= 65536:
        raise ValueError('无效的 pid 或 length')
    text = params['address'].strip()
    if not re.fullmatch(r'0[xX][0-9a-fA-F]+|[0-9]+', text):
        raise ValueError('子进程地址必须是绝对十六进制或十进制数，不能使用父进程表达式')
    address = int(text, 16 if text.lower().startswith('0x') else 10)
    status, started = _proc_status(pid), _proc_start(pid)
    tracer = int(status.get('TracerPid', '0'))
    parent_pid = int(gdb.selected_inferior().pid)
    if tracer != parent_pid:
        raise RuntimeError('TracerPid=%d，不是当前 inferior=%d；拒绝读取无关进程' % (tracer, parent_pid))
    if status.get('State', '').strip()[:1] not in ('t', 'T') or started is None:
        raise RuntimeError('tracee 未确认停止，拒绝把运行中的数据称为停止态快照')
    # /proc/mem access checks remain enforced by the kernel. Never seize the
    # tracee or inject ptrace calls into its real tracer as a fallback.
    fd = os.open('/proc/%d/mem' % pid, os.O_RDONLY)
    try:
        raw = os.pread(fd, length, address)
    finally:
        os.close(fd)
    after = _proc_status(pid)
    if (_proc_start(pid) != started or int(after.get('TracerPid', '0')) != tracer or
            after.get('State', '').strip()[:1] not in ('t', 'T')):
        raise RuntimeError('读取期间 tracee 身份或停止状态发生变化')
    if len(raw) != length:
        raise RuntimeError('tracee 内存短读：%d/%d' % (len(raw), length))
    return {'pid': pid, 'tracer_pid': tracer, 'address': hex(address), 'requested_length': length,
            'actual_length': len(raw), 'bytes_hex': ' '.join('%02x' % b for b in raw),
            'source': 'proc_mem', 'tracee_attached_by_tool': False}


def op_read_struct(params):
    if params['layout'] != 'linux_x86_64_user_regs':
        raise ValueError('unsupported struct ABI')
    if _ctx['state'] != 'stopped' or not inferior_alive():
        raise RuntimeError('结构体读取要求 stopped 状态')
    arch = gdb.newest_frame().architecture().name()
    if 'x86-64' not in arch or int(gdb.lookup_type('void').pointer().sizeof) != 8:
        raise RuntimeError('该布局要求 Linux x86-64 的 64 位 user_regs_struct')
    import struct
    names = ('r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi '
             'orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs').split()
    address = resolve_addr(params['address'])
    raw = bytes(gdb.selected_inferior().read_memory(address, 216))
    values = struct.unpack('<27Q', raw)
    return {'address': hex(address), 'layout': params['layout'], 'size': len(raw),
            'fields': {name: {'offset': i * 8, 'value_hex': hex(value), 'value_unsigned': value}
                       for i, (name, value) in enumerate(zip(names, values))},
            'source': 'saved_inferior_memory', 'live_tracee_registers': False,
            'capture_time_verified': False}


def op_memory_read(params):
    if not inferior_alive():
        raise RuntimeError("目标进程没有运行（内存不可读）")
    address = resolve_addr(params["address"])
    length = int(params.get("length", 16))
    try:
        memory = bytes(gdb.selected_inferior().read_memory(address, length))
    except Exception as exc:
        raise RuntimeError("读取内存 0x%x 失败: %s" % (address, exc))
    return {
        "address": hex(address),
        "requested_length": length,
        "actual_length": len(memory),
        "bytes_hex": " ".join("%02x" % b for b in memory),
        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in memory),
    }


def op_memory_snapshot(params):
    if _ctx["state"] != "stopped":
        raise RuntimeError("内存快照要求目标处于 stopped 状态")
    length = int(params["length"])
    if length < 1 or length > 1048576:
        raise ValueError("快照长度必须在 1..1048576 内")
    data = op_memory_read(params)
    if not params.get("explicit_destination"):
        mappings = op_mappings({})
        start = int(data["address"], 16)
        cursor, end = start, start + length
        for item in sorted(mappings["module_mappings"], key=lambda m: int(m["start"], 16)):
            lo, hi = int(item["start"], 16), int(item["end"], 16)
            if lo <= cursor < hi:
                cursor = min(end, hi)
            if cursor == end:
                break
        if cursor != end:
            raise ValueError("快照范围不完全属于主模块；请明确提供 static_address")
        data["mappings"] = mappings
    data["stop"] = _ctx["stop"]
    start = int(data["address"], 16)
    overlapping, unresolved = [], []
    for bp in gdb.breakpoints() or []:
        if not bp.enabled or bp.type != gdb.BP_BREAKPOINT:
            continue
        try:
            locations = list(bp.locations)
            if not locations:
                unresolved.append(int(bp.number))
            for location in locations:
                if location.address is None:
                    unresolved.append(int(bp.number))
                elif location.enabled and start <= int(location.address) < start + length:
                    overlapping.append({"number": int(bp.number), "address": hex(int(location.address))})
        except Exception:
            unresolved.append(int(bp.number))
    data["breakpoint_context"] = {"software_breakpoints_in_range": overlapping,
                                  "unresolved_software_breakpoints": sorted(set(unresolved)),
                                  "scope": "currently_enabled_breakpoint_locations",
                                  "previous_breakpoint_effects_known": False}
    return data


def op_memory_write(params):
    if not inferior_alive():
        raise RuntimeError("目标进程没有运行（内存不可写）")
    address = resolve_addr(params["address"])
    values = list(params["bytes"] or [])
    if not values or any(not isinstance(v, int) or v < 0 or v > 255 for v in values):
        raise ValueError("bytes 必须是非空的 0-255 整数列表")
    payload = bytes(bytearray(values))
    inf = gdb.selected_inferior()
    try:
        inf.write_memory(address, payload)
    except Exception as exc:
        raise RuntimeError("写入内存 0x%x 失败: %s" % (address, exc))
    try:
        readback = bytes(inf.read_memory(address, len(payload)))
    except Exception as exc:
        return {"address": hex(address), "written": len(payload),
                "readback_hex": None, "verified": False,
                "readback_error": str(exc)}
    return {"address": hex(address), "written": len(payload),
            "readback_hex": " ".join("%02x" % b for b in readback),
            "verified": readback == payload}


def op_memory_search(params):
    if not inferior_alive():
        raise RuntimeError("目标进程没有运行（内存不可搜索）")
    start = resolve_addr(params["start"])
    length = int(params["length"])
    end = start + length
    pattern = [int(v) for v in params["pattern"]]
    if not pattern:
        raise ValueError("pattern 不能为空")
    max_hits = int(params.get("max_hits", 100))
    # GDB's end address is inclusive; APRE length describes [start, end).
    command = "find /b%d %s, +%d, %s" % (
        max_hits + 1, hex(start), length, ", ".join(str(v) for v in pattern))
    try:
        out = gdb.execute(command, to_string=True)
    except Exception as exc:
        raise RuntimeError("搜索失败: %s" % exc)
    hits, warnings = [], []
    for line in out.splitlines():
        match = re.match(r"^(0x[0-9a-fA-F]+)", line.strip())
        if match:
            hits.append(match.group(1))
        elif line.strip() and "warning" in line.lower():
            warnings.append(line.strip())
    return {"start": hex(start), "end": hex(end), "pattern_hex": " ".join("%02x" % v for v in pattern),
            "hits": hits[:max_hits], "hit_count": min(len(hits), max_hits),
            "truncated": len(hits) > max_hits,
            "warnings": warnings}


def op_backtrace(params):
    if not inferior_alive():
        raise RuntimeError("目标进程没有运行（没有调用栈）")
    depth = int(params.get("depth", 20))
    frames = []
    frame = gdb.newest_frame()
    level = 0
    while frame is not None and level < depth:
        entry = {"level": level}
        try:
            entry["pc"] = hex(int(frame.pc()))
        except Exception:
            pass
        try:
            entry["name"] = frame.name()
        except Exception:
            entry["name"] = None
        try:
            function = frame.function()
            entry["function"] = function.name if function is not None else None
        except Exception:
            entry["function"] = None
        frames.append(entry)
        frame = frame.older()
        level += 1
    return {"frames": frames, "count": len(frames)}


def op_disassemble(params):
    if not inferior_alive():
        raise RuntimeError("目标进程没有运行（无法反汇编运行时内存）")
    if params.get("address"):
        address = resolve_addr(params["address"])
    else:
        address = current_pc()
    count = int(params.get("count", 16))
    out = gdb.execute("x/%di %s" % (count, hex(address)), to_string=True)
    pattern = re.compile(r"^(?:=>\s*)?(0x[0-9a-fA-F]+)(?:\s+<([^>]*)>)?:\s*(.*)$")
    instructions, addresses = [], []
    for line in out.splitlines():
        match = pattern.match(line.strip())
        if match:
            addresses.append(int(match.group(1), 16))
            instructions.append({
                "address": match.group(1),
                "symbol": match.group(2) or "",
                "text": match.group(3).strip(),
            })
    inf = gdb.selected_inferior()
    for index, item in enumerate(instructions):
        item["bytes_hex"] = ""
        try:
            addr = addresses[index]
            decoded = gdb.selected_frame().architecture().disassemble(addr, count=1)[0]
            size = decoded["length"]
            item["length"] = size
            memory = bytes(inf.read_memory(addr, size))
            item["bytes_hex"] = " ".join("%02x" % b for b in memory)
        except Exception:
            pass
    return {"address": hex(address), "count_requested": count,
            "instructions": instructions}


def op_evaluate(params):
    if not inferior_alive() or _ctx["state"] != "stopped":
        raise RuntimeError("表达式求值要求存活的目标处于 stopped 状态")
    expression = params["expression"]
    try:
        value = gdb.parse_and_eval(expression)
    except Exception as exc:
        raise RuntimeError("表达式求值失败: %s。gdb_evaluate 仅接受表达式，不接受 x/print/call 等 GDB 命令；"
                           "内存检查请用 gdb_memory_read，函数调用请传 fn(args)（不带 call）。"
                           "无调试类型时需正确的函数指针类型；底层调用失败不代表未产生副作用。" % exc)
    result = _value_fields(value)
    try:
        code = value.type.code
        if code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_ARRAY):
            try:
                result["string"] = value.string(encoding="utf-8", errors="replace",
                                                length=512)
            except Exception:
                pass
    except Exception:
        pass
    result["expression"] = expression
    return result


_BP_TYPE_NAMES = {
    getattr(gdb, "BP_BREAKPOINT", 0): "software",
    getattr(gdb, "BP_HARDWARE_BREAKPOINT", 1): "hardware",
    getattr(gdb, "BP_WATCHPOINT", 2): "watchpoint",
    getattr(gdb, "BP_CATCHPOINT", 3): "catchpoint",
    getattr(gdb, "BP_TRACEPOINT", 4): "tracepoint",
}
_WATCH_TYPES = {"watch_read": gdb.WP_READ, "watch_write": gdb.WP_WRITE,
                "watch_access": gdb.WP_ACCESS}


def _bp_dict(bp):
    entry = {"number": int(bp.number), "type": _BP_TYPE_NAMES.get(bp.type, "unknown"),
             "location": str(bp.location), "enabled": bool(bp.enabled),
             "hit_count": int(bp.hit_count)}
    for attr in ("pending", "temporary", "condition"):
        if hasattr(bp, attr):
            try:
                entry[attr] = getattr(bp, attr)
            except Exception:
                pass
    return entry


def op_breakpoint_set(params):
    if not inferior_alive():
        raise RuntimeError("目标进程没有运行（无法设置断点）")
    bp_type = params.get("type", "software")
    location = params.get("location")
    temporary = bool(params.get("temporary"))
    condition = params.get("condition")
    before = set(int(b.number) for b in gdb.breakpoints())
    log("breakpoint_set type=%s location=%r existing=%s" % (bp_type, location, sorted(before)))
    if bp_type in ("software", "hardware"):
        if not location:
            raise ValueError("software/hardware 断点需要 location")
        kind = gdb.BP_HARDWARE_BREAKPOINT if bp_type == "hardware" else gdb.BP_BREAKPOINT
        try:
            bp = gdb.Breakpoint(location, kind, temporary=temporary)
        except Exception as exc:
            raise RuntimeError("断点创建失败 (%s): %s" % (location, exc))
        if condition:
            try:
                bp.condition = condition
            except Exception as exc:
                bp.delete()
                raise RuntimeError("断点条件设置失败: %s" % exc)
    elif bp_type in _WATCH_TYPES:
        if not location:
            raise ValueError("watch_* 需要监视表达式 location")
        bp = gdb.Breakpoint(location, gdb.BP_WATCHPOINT, _WATCH_TYPES[bp_type],
                            temporary=temporary)
    elif bp_type == "catch_syscall":
        command = "catch syscall" + (" " + location if location else "")
        out = gdb.execute(command, to_string=True)
        return {"type": "catch_syscall", "output": out.strip(),
                "message": "catch syscall 已设置（可通过 breakpoint list 查看编号）"}
    elif bp_type == "catch_signal":
        if not location:
            raise ValueError("catch_signal 需要信号名 location（如 SIGALRM）")
        out = gdb.execute("catch signal %s" % location, to_string=True)
        return {"type": "catch_signal", "output": out.strip(),
                "message": "catch signal 已设置（可通过 breakpoint list 查看编号）"}
    else:
        raise ValueError("未知断点类型: %s" % bp_type)
    after = set(int(b.number) for b in gdb.breakpoints())
    created = after - before
    return {"created": sorted(created), "breakpoint": _bp_dict(bp)}


def op_breakpoint_remove(params):
    number = params.get("number")
    location = params.get("location")
    removed = []
    if number is not None:
        for bp in gdb.breakpoints():
            if int(bp.number) == int(number):
                bp.delete()
                removed.append(int(number))
        if not removed:
            raise RuntimeError("没有编号为 %s 的断点" % number)
    elif location:
        normalized = location.strip()
        if re.fullmatch(r"0[xX][0-9a-fA-F]+|[0-9]+", normalized):
            normalized = '*0x%x' % int(normalized, 16 if normalized.lower().startswith('0x') else 10)
        for bp in gdb.breakpoints():
            if str(bp.location) == location or (bp.type in (gdb.BP_BREAKPOINT, gdb.BP_HARDWARE_BREAKPOINT) and str(bp.location) == normalized):
                removed.append(int(bp.number))
                bp.delete()
        if not removed:
            raise RuntimeError("没有位于 %s 的断点（用 breakpoint list 核对）" % location)
    else:
        raise ValueError("remove 需要 number 或 location")
    return {"removed": removed}


def op_breakpoint_remove_all(params):
    before = [int(b.number) for b in gdb.breakpoints()]
    gdb.execute("delete breakpoints", to_string=True)
    return {"removed": before}


def op_breakpoint_list(params):
    return {"breakpoints": [_bp_dict(b) for b in gdb.breakpoints()]}


def op_thread_list(params):
    return {"threads": inferior_threads()}


def op_thread_select(params):
    thread_id = params.get("thread_id")
    if thread_id is None:
        raise ValueError("select 需要 thread_id")
    try:
        gdb.execute("thread %d" % int(thread_id), to_string=True)
    except Exception as exc:
        raise RuntimeError("切换线程失败: %s" % exc)
    return {"selected": int(thread_id), "threads": inferior_threads()}


_SET_COMMANDS = {
    "follow_fork_mode": "follow-fork-mode",
    "follow_exec_mode": "follow-exec-mode",
    "scheduler_locking": "scheduler-locking",
    "detach_on_fork": "detach-on-fork",
    "stop_on_solib_events": "stop-on-solib-events",
    "disable_randomization": "disable-randomization",
}
_SET_VALUES = {
    "follow-fork-mode": {"parent", "child"},
    "follow-exec-mode": {"same", "new"},
    "scheduler-locking": {"off", "on", "step", "replay"},
    "detach-on-fork": {"on", "off"},
    "stop-on-solib-events": {"0", "1"},
    "disable-randomization": {"on", "off"},
}


def op_set(params):
    setting = params.get("setting")
    value = str(params.get("value"))
    command = _SET_COMMANDS.get(setting)
    if command is None:
        raise ValueError("未知设置: %s" % setting)
    if value not in _SET_VALUES[command]:
        raise ValueError("%s 的取值必须是 %s 之一" % (setting, sorted(_SET_VALUES[command])))
    gdb.execute("set %s %s" % (command, value), to_string=True)
    show = gdb.execute("show %s" % command, to_string=True)
    return {"setting": setting, "value": value, "show_output": show.strip()}


def op_handle_signal(params):
    signal = params.get("signal")
    if not signal:
        raise ValueError("signal 不能为空")
    stop = "stop" if params.get("stop") else "nostop"
    print_ = "print" if params.get("print") else "noprint"
    pass_ = "pass" if params.get("pass_to_program", True) else "nopass"
    command = "handle %s %s %s %s" % (signal, stop, print_, pass_)
    try:
        out = gdb.execute(command, to_string=True)
    except Exception as exc:
        raise RuntimeError("信号配置失败: %s" % exc)
    return {"signal": signal, "stop": bool(params.get("stop")),
            "print": bool(params.get("print")),
            "pass_to_program": bool(params.get("pass_to_program", True)),
            "output": out.strip()}


def op_mappings(params):
    try:
        out = gdb.execute("info proc mappings", to_string=True)
    except Exception as exc:
        raise RuntimeError("无法读取进程映射（远端目标通常不支持）: %s" % exc)
    pattern = re.compile(
        r"^(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s+(\S+)\s+(.+?)\s*$")
    mappings = []
    for line in out.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        mappings.append({
            "start": match.group(1), "end": match.group(2),
            "size": match.group(3), "offset": match.group(4),
            "perms": match.group(5), "objfile": match.group(6).strip(),
        })
    if not mappings:
        raise RuntimeError("进程映射为空或格式无法解析")
    target = _ctx["target"]
    module_mappings = []
    if target:
        try:
            target_real = os.path.realpath(target)
        except OSError:
            target_real = target
        module_mappings = [m for m in mappings
                           if m["objfile"] == target_real or m["objfile"] == target]
    if target and not module_mappings:
        raise RuntimeError("未找到目标文件的运行时映射，拒绝使用其他模块的基址")
    if not module_mappings:
        # attach 且未提供符号文件：取 offset 为 0 的可执行映射（排除 vdso 等内核对象）
        module_mappings = [m for m in mappings
                           if int(m["offset"], 16) == 0 and "x" in m["perms"]
                           and not m["objfile"].startswith("[")]
    if not module_mappings:
        module_mappings = mappings
    base = min(int(m["start"], 16) for m in module_mappings)
    module_path = module_mappings[0]["objfile"] if module_mappings else None
    return {"runtime_base": hex(base), "module_path": module_path,
            "module_mappings": module_mappings, "mapping_count": len(mappings)}


def op_kill(params):
    alive = inferior_alive()
    if alive:
        try:
            gdb.execute("kill", to_string=True)
        except Exception as exc:
            raise RuntimeError("结束目标进程失败: %s" % exc)
    set_state("closed", closed_by="kill")
    return {"killed": alive, "exit_code": _ctx["exit_code"]}


def op_detach(params):
    alive = inferior_alive()
    if alive:
        try:
            gdb.execute("detach", to_string=True)
        except Exception as exc:
            raise RuntimeError("分离失败: %s" % exc)
    set_state("detached")
    return {"detached": alive}


def op_close(params):
    if inferior_alive():
        try:
            gdb.execute("kill", to_string=True)
        except Exception:
            pass
    set_state("closed", closed_by="client_request")
    return {"closed": True}


def op_ping(params):
    return {"pong": True, "state": _ctx["state"], "gdb_pid": os.getpid(),
            'session_id': _ctx['session_id'], 'inferior_pid': int(gdb.selected_inferior().pid) or _ctx.get('inferior_pid'),
            'inferior_alive': inferior_alive(),
            'live_inferior_pids': [int(inf.pid) for inf in gdb.inferiors() if inf.pid]}


_OPERATIONS = {
    "ping": op_ping,
    "continue": op_continue,
    "step": op_step,
    "trace": op_trace,
    "state": op_state,
    "output": op_output,
    "input": op_input,
    "registers": op_registers,
    "memory_read": op_memory_read,
    "tracee_read": op_tracee_read,
    "read_struct": op_read_struct,
    "memory_snapshot": op_memory_snapshot,
    "memory_write": op_memory_write,
    "memory_search": op_memory_search,
    "backtrace": op_backtrace,
    "disassemble": op_disassemble,
    "evaluate": op_evaluate,
    "breakpoint_set": op_breakpoint_set,
    "breakpoint_remove": op_breakpoint_remove,
    "breakpoint_remove_all": op_breakpoint_remove_all,
    "breakpoint_list": op_breakpoint_list,
    "thread_list": op_thread_list,
    "thread_select": op_thread_select,
    "set": op_set,
    "handle_signal": op_handle_signal,
    "mappings": op_mappings,
    "kill": op_kill,
    "detach": op_detach,
    "close": op_close,
}


# ── socket 服务循环 ─────────────────────────────────────────────────

def _recv_request(conn):
    """读取一行 JSON 请求（有大小上限）。"""
    conn.settimeout(60)
    buffer = b""
    while b"\n" not in buffer:
        chunk = conn.recv(65536)
        if not chunk:
            if not buffer:
                return None
            break
        buffer += chunk
        if len(buffer) > MAX_REQUEST_BYTES:
            raise ValueError("请求超过大小上限")
    return buffer.decode("utf-8", "replace")


def handle_connection(conn):
    _ctx["last_activity"] = time.time()
    request_id = None
    try:
        raw = _recv_request(conn)
        if raw is None:
            return
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError("请求必须是对象")
        request_id = request.get("id")
        op = request.get("op")
        params = request.get("params") or {}
        handler = _OPERATIONS.get(op)
        if handler is None:
            raise ValueError("未知操作: %s" % op)
        try:
            data = handler(params)
        except KeyboardInterrupt:
            raise
        response = {"id": request_id, "ok": True, "data": data}
    except KeyboardInterrupt:
        response = {"id": request_id, "ok": False,
                    "error": {"code": "gdb.interrupted",
                              "message": "操作被 SIGINT 中断，目标进程已停止。"}}
    except Exception as exc:
        log("op failed: %s\n%s" % (exc, traceback.format_exc()[-1200:]))
        response = {"id": request_id, "ok": False,
                    "error": {"code": "gdb.operation_failed",
                              "message": str(exc),
                              "exception_type": type(exc).__name__,
                              "snapshot": failure_snapshot()}}
    finally:
        write_session()
    try:
        conn.sendall(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
    except OSError as exc:
        log("response send failed: %s" % exc)


def serve(idle_timeout):
    socket_path = _ctx["socket_path"]
    try:
        os.unlink(socket_path)
    except OSError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(socket_path)
    os.chmod(socket_path, 0o600)
    listener.listen(4)
    _ctx["startup_warnings"] = list(_ctx["warnings"])
    _ctx["warnings"] = []
    _ctx["ready"] = True
    write_session()
    log("listening on %s" % socket_path)
    deadline = time.time() + idle_timeout
    try:
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                log("idle timeout reached")
                if inferior_alive():
                    try:
                        gdb.execute("kill", to_string=True)
                    except Exception:
                        pass
                set_state("closed", closed_by="idle_timeout")
                return
            try:
                readable, _, _ = select.select([listener], [], [], min(remaining, 2.0))
            except KeyboardInterrupt:
                # 空闲时收到 SIGINT（例如 gdb_interrupt 的竞态窗口）：
                # 会话保持，仅刷新空闲计时后继续服务。
                deadline = time.time() + idle_timeout
                continue
            if not readable:
                continue
            try:
                conn, _ = listener.accept()
            except KeyboardInterrupt:
                continue
            try:
                handle_connection(conn)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            if _ctx["state"] in ("closed", "detached"):
                return
            deadline = time.time() + idle_timeout
    finally:
        try:
            listener.close()
        except OSError:
            pass
        try:
            os.unlink(socket_path)
        except OSError:
            pass


def main():
    if not SESSION_DIR:
        log("APRE_SESSION_DIR 未设置")
        return 1
    idle_timeout = 3600
    try:
        with open(os.path.join(SESSION_DIR, INIT_FILE), "r") as fh:
            init = json.loads(fh.read())
        idle_timeout = int(init.get("idle_timeout", 3600))
        if idle_timeout <= 0:
            idle_timeout = 3600
    except (OSError, ValueError) as exc:
        log("init.json 读取失败: %s" % exc)
    try:
        init_session()
        serve(idle_timeout)
    except KeyboardInterrupt:
        # 初始化阶段被 SIGINT 打断（如 target remote 连接超时被看门狗中断）：
        # 必须落盘 error 状态，客户端才能得到明确诊断，会话目录也能被自动回收。
        log("bridge interrupted at top level, state=%s" % _ctx["state"])
        if _ctx["state"] not in ("stopped", "exited", "detached", "closed"):
            _ctx["fatal"] = True
            _ctx["error"] = {"code": "gdb.init_interrupted",
                             "message": "会话初始化被 SIGINT 中断（目标加载/附加/连接未完成）。",
                             "exception_type": "KeyboardInterrupt",
                             "snapshot": failure_snapshot()}
            _ctx["state"] = "error"
            write_session()
            return 1
    except Exception as exc:
        log("fatal: %s\n%s" % (exc, traceback.format_exc()[-2000:]))
        _ctx["fatal"] = True
        _ctx["error"] = {"code": "gdb.init_failed", "message": str(exc),
                         "exception_type": type(exc).__name__,
                         "snapshot": failure_snapshot()}
        _ctx["state"] = "error"
        write_session()
        return 1
    finally:
        _pty_done.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
