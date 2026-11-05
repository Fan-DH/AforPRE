"""Transfer a stopped inferior snapshot without asking the caller to encode bytes."""

import hashlib
import json
from pathlib import Path
import uuid

from contracts.results import ToolResult
from tools.base import ProviderError
from tools.gdb import session
from tools.gdb.common import SOFTWARE_BREAKPOINT_LIMITATION
from tools.ghidra.runner import _project_key


def apply_memory(provider, args):
    workspace = provider.config.workspace
    sid = args['session_id']
    session.session_dir(workspace, sid)
    state = session.read_session_state(workspace, sid)
    target = state.get('target')
    if not target or not Path(target).is_file():
        raise ProviderError('会话需要可用的本地 target_path 才能更新 Ghidra 工程')
    fingerprint = _project_key(target)
    if not state.get('target_sha256') or state['target_sha256'] != fingerprint:
        raise ProviderError('目标文件已变化或旧会话缺少内容指纹；请重新建立调试会话，避免 patch 错误工程')
    snapshot = session.rpc(workspace, sid, 'memory_snapshot', {
        'address': args['address'], 'length': args['length'],
        'explicit_destination': 'static_address' in args,
    })
    raw = bytes.fromhex(snapshot['bytes_hex'])
    if len(raw) != args['length'] or snapshot['actual_length'] != args['length']:
        raise ProviderError('内存读取不完整，未修改 Ghidra 工程')
    if 'static_address' in args:
        destination = int(args['static_address'], 16)
    else:
        base = provider.runner.run_script(target, 'debug_image_base.py', {}, expected_sha256=fingerprint)['image_base']
        destination = (int(snapshot['address'], 16) - int(snapshot['mappings']['runtime_base'], 16)
                       + int(base, 16))
    if destination < 0:
        raise ProviderError('换算出的 Ghidra 地址为负，未修改工程')
    # Archive the captured bytes before attempting any mutation, also on failure.
    root = Path(workspace).resolve() / 'memory_snapshots'
    root.mkdir(parents=True, exist_ok=True)
    artifact = root / (uuid.uuid4().hex + '.bin')
    artifact.write_bytes(raw)
    metadata = {'session_id': sid, 'target': target, 'target_sha256': fingerprint,
                'runtime_address': snapshot['address'], 'static_address': hex(destination),
                'length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                'snapshot_path': str(artifact), 'stop': snapshot.get('stop'),
                'breakpoint_context': snapshot.get('breakpoint_context')}
    original = artifact.with_suffix('.original.bin')
    metadata['original_path'] = str(original)
    artifact.with_suffix('.json').write_text(json.dumps(metadata, ensure_ascii=False), encoding='utf-8')
    try:
        payload = provider.runner.run_script(target, 'patch_bytes.py', {
            'address': hex(destination), 'bytes': list(raw),
            'rebuild_code': args.get('rebuild_code', True),
            'reanalyze': args.get('reanalyze', True),
            'original_path': str(original), 'include_bytes': False,
        }, read_only=False, expected_sha256=fingerprint)
    except ProviderError as exc:
        exc.diagnostics.append({'code': 'ghidra.memory_snapshot', 'severity': 'info',
                                'message': '本次内存快照已归档', 'details': metadata,
                                'suggestions': []})
        raise
    limitations = list(payload.get('_limitations', []))
    diagnostics = list(payload.get('_diagnostics', []))
    context = snapshot.get('breakpoint_context') or {}
    if context.get('software_breakpoints_in_range') or context.get('unresolved_software_breakpoints'):
        limitations.append(SOFTWARE_BREAKPOINT_LIMITATION)
        diagnostics.append({'code': 'ghidra.snapshot_software_breakpoints', 'severity': 'warning',
                            'message': '快照范围存在软件断点，或部分软件断点位置无法核实；不能保证字节未受其影响。',
                            'details': context, 'suggestions': [SOFTWARE_BREAKPOINT_LIMITATION]})
    return ToolResult(data={**{k: v for k, v in payload.items() if not k.startswith('_')},
                            **metadata, 'original_path': str(original)},
                      limitations=limitations, diagnostics=diagnostics)
