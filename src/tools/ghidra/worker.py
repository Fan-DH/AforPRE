"""A reusable headless process per content-addressed project (shared by CLI/MCP).

All methods run under the runner's project flock. Requests are never replayed
once accepted; failures and timeouts report unconfirmed save state.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import uuid

from processes import track_process, pid_alive
from tools.ghidra.diagnostics import error, diagnostic, output_warnings


def _identity(pid):
    try:
        return Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError, TypeError):
        return None


def _alive(state):
    pid = state.get('pid')
    return pid_alive(pid) and state.get('identity') == _identity(pid)


class ProjectWorker:
    def __init__(self, runner, project_dir):
        self.runner = runner
        self.project_dir = project_dir
        self.root = Path(runner.workspace) / 'ghidra_projects' / '.workers'
        self.root.mkdir(parents=True, exist_ok=True)
        self.marker = self.root / (Path(project_dir).name + '.json')

    def state(self):
        try:
            return json.loads(self.marker.read_text())
        except (OSError, ValueError):
            return {}

    def stop(self):
        state = self.state()
        if _alive(state):
            (Path(state['directory']) / 'shutdown').touch()
            deadline = time.monotonic() + 10
            while _alive(state) and time.monotonic() < deadline:
                time.sleep(.05)
            if _alive(state):
                os.killpg(state['pid'], signal.SIGKILL)
                deadline = time.monotonic() + 5
                while _alive(state) and time.monotonic() < deadline:
                    time.sleep(.05)
                if _alive(state):
                    raise error('ghidra.worker_stop_failed', 'Ghidra worker 退出未确认，未删除工程')
        self.marker.unlink(missing_ok=True)
        if state.get('directory'):
            shutil.rmtree(state['directory'], ignore_errors=True)

    def _fingerprint(self):
        from tools.ghidra.runner import SCRIPTS_DIR
        digest = hashlib.sha256()
        digest.update(self.runner._startup_environment['environment_fingerprint'].encode())
        for path in sorted(Path(SCRIPTS_DIR).glob('*.py')):
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
        return digest.hexdigest()

    def ensure(self):
        from tools.ghidra.runner import SCRIPTS_DIR, PROJECT_NAME, PROGRAM_NAME
        state = self.state()
        fingerprint = self._fingerprint()
        if _alive(state) and state.get('fingerprint') == fingerprint:
            try:
                ready = json.loads((Path(state['directory']) / 'ready.json').read_text())
                if ready['idle_deadline'] > time.time() + 1:
                    return state, True
            except (OSError, ValueError, KeyError):
                pass
        self.stop()
        directory = self.root / (Path(self.project_dir).name + '-' + uuid.uuid4().hex)
        directory.mkdir(mode=0o700)
        logs = Path(self.runner.workspace) / 'ghidra_logs'
        logs.mkdir(parents=True, exist_ok=True)
        log_path = logs / (directory.name + '.worker.log')
        idle = int(os.environ.get('APRE_GHIDRA_WORKER_IDLE', '300'))
        if idle < 1:
            raise ValueError('APRE_GHIDRA_WORKER_IDLE 必须为正整数')
        command = [self.runner._headless, self.project_dir, PROJECT_NAME,
                   '-process', PROGRAM_NAME, '-noanalysis', '-scriptPath', SCRIPTS_DIR,
                   '-postScript', '_serve.py', json.dumps({'directory': str(directory), 'idle_timeout': idle})]
        with log_path.open('wb') as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT, env=self.runner._process_env, start_new_session=True)
        state = {'pid': process.pid, 'identity': _identity(process.pid),
                 'directory': str(directory), 'log_path': str(log_path), 'fingerprint': fingerprint}
        self.marker.write_text(json.dumps(state))
        track_process(process)
        deadline = time.monotonic() + self.runner.timeout
        while time.monotonic() < deadline:
            if (directory / 'ready.json').exists():
                return state, False
            if not _alive(state):
                self._failed(state, 'Ghidra worker 在就绪前退出')
            time.sleep(.05)
        self._failed(state, 'Ghidra worker 启动超时', timeout=True)

    def _failed(self, state, message, timeout=False):
        try:
            with Path(state['log_path']).open('rb') as stream:
                stream.seek(0, 2)
                stream.seek(max(0, stream.tell() - 8000))
                tail = stream.read().decode('utf-8', 'replace')
        except OSError:
            tail = ''
        if _alive(state):
            os.killpg(state['pid'], signal.SIGKILL)
        self.stop()
        raise error('ghidra.worker_timeout' if timeout else 'ghidra.worker_failed', message,
                    status='timeout' if timeout else 'error',
                    details={'log_path': state['log_path'], 'log_tail': tail},
                    limitations=['请求可能已执行，保存状态未确认；未自动重放请求。'])

    def run(self, script, params, read_only):
        state, reused = self.ensure()
        directory = Path(state['directory'])
        token = uuid.uuid4().hex
        request = directory / (token + '.request.json')
        response = directory / (token + '.response.json')
        temporary = request.with_suffix('.tmp')
        temporary.write_text(json.dumps({'script': script, 'arguments': params,
                                         'read_only': read_only}, ensure_ascii=True))
        log_offset = Path(state['log_path']).stat().st_size if reused else 0
        temporary.replace(request)
        started = time.monotonic()
        while time.monotonic() - started < self.runner.timeout:
            if response.exists():
                result = json.loads(response.read_text())
                response.unlink()
                with Path(state['log_path']).open('rb') as stream:
                    stream.seek(log_offset)
                    log_text = stream.read().decode('utf-8', 'replace')
                warnings, limitations = output_warnings(log_text, '', 'script:' + script)
                result.setdefault('_diagnostics', []).extend(warnings)
                result.setdefault('_limitations', []).extend(limitations)
                result.setdefault('_diagnostics', []).append(diagnostic(
                    'ghidra.worker_request', '复用 Ghidra 工程执行请求', severity='info',
                    details={'stage': 'process', 'worker_pid': state['pid'], 'worker_reused': reused,
                             'log_path': state['log_path'], 'log_offset': log_offset,
                             'duration_seconds': time.monotonic() - started}))
                if not read_only and '_error' not in result and not result.get('_saved'):
                    self._failed(state, 'worker 未确认修改已保存')
                return result
            if not _alive(state):
                self._failed(state, 'Ghidra worker 在请求完成前退出')
            time.sleep(.025)
        self._failed(state, 'Ghidra worker 请求超时', timeout=True)
