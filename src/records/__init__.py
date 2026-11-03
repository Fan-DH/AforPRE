"""记录与过程存储层。

只负责「存储」；记录的数据结构见 contracts.record。
"""

from .store import RecordStore

__all__ = ["RecordStore"]