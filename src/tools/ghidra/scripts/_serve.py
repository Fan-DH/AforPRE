# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
"""Keep one program open; serialize requests and save before acknowledging writes."""
import json
import os
import time
from _common import dispatch, JAVA_ERRORS

options = json.loads(getScriptArgs()[0])
root = options['directory']
idle = options['idle_timeout']


def publish(name, value):
    path = os.path.join(root, name)
    with open(path + '.tmp', 'w') as stream:
        json.dump(value, stream, ensure_ascii=True)
    os.rename(path + '.tmp', path)


# GhidraScript opens a transaction around the entire script. End it before
# entering the service loop so each request can commit/rollback and save itself.
end(True)
publish('ready.json', {'ready': True, 'idle_deadline': time.time() + idle})
last_activity = time.time()
try:
    while time.time() - last_activity < idle:
        if os.path.exists(os.path.join(root, 'shutdown')):
            break
        requests = sorted(name for name in os.listdir(root) if name.endswith('.request.json'))
        if not requests:
            time.sleep(0.025)
            continue
        for name in requests:
            path = os.path.join(root, name)
            active = path.replace('.request.json', '.active.json')
            os.rename(path, active)  # Accepted: never automatically replay this operation.
            with open(active) as stream:
                request = json.load(stream)
            start()
            try:
                result = dispatch(globals(), envelope=request, emit=False)
                success = '_error' not in result
                end(success and not request.get('read_only', True))
                if success and not request.get('read_only', True):
                    currentProgram.save('APRE request', monitor)
                    result['_saved'] = True
                publish(name.replace('.request.json', '.response.json'), result)
            except JAVA_ERRORS as exc:
                end(False)
                publish(name.replace('.request.json', '.response.json'), {
                    '_error': 'Worker execution/save failed: %s' % exc,
                    '_diagnostics': [{'code': 'ghidra.worker_save_failed', 'severity': 'error',
                        'message': '%s' % exc, 'details': {}, 'suggestions': []}],
                    '_limitations': ['Project save is unconfirmed; inspect the project before retrying.']})
                # Do not continue with potentially unsaved in-memory state.
                raise
            finally:
                os.unlink(active)
            last_activity = time.time()
            publish('ready.json', {'ready': True, 'idle_deadline': last_activity + idle})
finally:
    try:
        os.unlink(os.path.join(root, 'ready.json'))
    except OSError:
        pass
