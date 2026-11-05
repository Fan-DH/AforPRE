"""Artifacts outlive debugger sessions and never overwrite caller files."""
from pathlib import Path
import tempfile


def artifact_directory(workspace, kind):
    root = Path(workspace).resolve() / 'artifacts' / kind
    root.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=kind + '-', dir=str(root)))
