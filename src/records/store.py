"""记录与过程存储。

第一版使用工作目录下的 JSONL 文件，不需要数据库或向量库。
"""

from __future__ import annotations

import json
import os
import uuid
import fcntl
from dataclasses import dataclass

from contracts.record import Record


@dataclass
class RecordStore:
    workspace: str

    def __post_init__(self) -> None:
        os.makedirs(self.workspace, exist_ok=True)

    def _append(self, filename: str, record: dict) -> None:
        path = os.path.join(self.workspace, filename)
        with open(path, "a", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                fh.flush()
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def record(self, record: Record) -> str:
        """写入一条记录并返回其 id。"""
        self._append("record.jsonl", record.to_dict())
        return record.id

    def record_call(self, call: dict) -> None:
        """写入一条调用记录，关联到记录 id。"""
        self._append("calls.jsonl", call)

    @staticmethod
    def new_id() -> str:
        return f"rec-{uuid.uuid4().hex}"
