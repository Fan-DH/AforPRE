"""Liveness and cleanup for APRE-owned child process groups."""

import os
from pathlib import Path
import signal
import threading

_children = set()
_lock = threading.RLock()


def pid_alive(pid) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        # kill(pid, 0) also succeeds for zombies, which cannot serve requests.
        fields = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
        if fields[0] in ("Z", "X"):
            return False
    except (OSError, IndexError):
        pass
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def track_process(process):
    """Reap children even when a long-lived MCP server has finished the call.

    Normal worker exit leaves detached GDB sessions running. Explicit worker
    cancellation calls terminate_children to stop groups still owned by it.
    """
    with _lock:
        _children.add(process)

    def reap():
        try:
            process.wait()
        finally:
            with _lock:
                _children.discard(process)

    threading.Thread(target=reap, daemon=True).start()
    return process


def terminate_children():
    with _lock:
        children = list(_children)
    for process in children:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    for process in children:
        process.wait(timeout=5)
