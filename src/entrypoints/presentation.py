"""Compact transport views; persisted ToolResult remains lossless."""
from tools.gdb.common import GENERAL_LIMITATIONS

_ROUTINE_CODES = {'ghidra.worker_request', 'ghidra.project', 'ghidra.invocation'}
_SNAPSHOT_KEYS = {'state', 'stop', 'exit_code', 'target', 'last_command'}


def present_result(result, detail='compact'):
    out = result.to_dict()
    if detail == 'full':
        return out
    removed = {'diagnostics': 0, 'limitations': 0, 'snapshot_fields': 0}

    def compact(envelope):
        failed = envelope.get('status', 'ok') != 'ok'
        diagnostics = envelope.get('diagnostics', [])
        kept = [d for d in diagnostics if failed or not (
            d.get('severity') == 'info' and d.get('code') in _ROUTINE_CODES)]
        removed['diagnostics'] += len(diagnostics) - len(kept)
        for diagnostic in kept:
            # Only summarize the known GDB failure snapshot, preserving root error,
            # parameters, stop reason, and all diagnostics of unrelated engines.
            details = diagnostic.get('details', {})
            snapshot = details.get('snapshot')
            if diagnostic.get('code', '').startswith('gdb.') and isinstance(snapshot, dict):
                removed['snapshot_fields'] += len(snapshot.keys() - _SNAPSHOT_KEYS)
                details['snapshot'] = {key: value for key, value in snapshot.items() if key in _SNAPSHOT_KEYS}
        if 'diagnostics' in envelope:
            envelope['diagnostics'] = kept
        limitations = envelope.get('limitations', [])
        kept = [item for item in limitations if failed or item not in GENERAL_LIMITATIONS]
        removed['limitations'] += len(limitations) - len(kept)
        if 'limitations' in envelope:
            envelope['limitations'] = kept
        data = envelope.get('data')
        if isinstance(data, dict):
            children = data.get('results', [])
            for child in children if isinstance(children, list) else []:
                if isinstance(child, dict) and 'status' in child:
                    compact(child)
    compact(out)
    if any(removed.values()):
        out['omitted'] = {key: count for key, count in removed.items() if count}
    return out
