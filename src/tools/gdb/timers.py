"""Advisory ELF import probe; never treats imports as executed timer calls."""
import os
import subprocess

_TIMER_SYMBOLS = {'alarm', 'ualarm', 'setitimer', 'timer_create', 'timer_settime', 'timerfd_settime'}


def probe_timers(path):
    try:
        proc = subprocess.run(['readelf', '--dyn-syms', '--wide', path],
                              capture_output=True, text=True, timeout=10,
                              env={**os.environ, 'LC_ALL': 'C'})
        if proc.returncode:
            return {'checked': False, 'symbols': [], 'error': proc.stderr.strip()[:500]}
        symbols = set()
        for line in proc.stdout.splitlines():
            parts = line.split()
            if 'UND' in parts and len(parts) >= 8:
                name = parts[7].split('@')[0]
                if name in _TIMER_SYMBOLS:
                    symbols.add(name)
        return {'checked': True, 'symbols': sorted(symbols), 'scope': 'dynamic_imports',
                'execution_confirmed': False}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'checked': False, 'symbols': [], 'error': str(exc)[:500]}
