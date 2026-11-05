# -*- coding: utf-8 -*-
"""gdb 引擎：APRE 的动态调试能力（与 binutils / ghidra 平级的独立引擎）。

- probe.py      环境探测（gdb 定位、版本、Python 支持、ptrace 约束）
- gdb_bridge.py 运行在 gdb 内嵌 Python 中的 socket 服务（会话状态机与操作实现）
- session.py    服务进程侧：会话启动、RPC 客户端、注册表扫描与清理
- lifecycle.py / control.py / data.py / breakpoints.py / mapping.py：操作实现
- mapping.py    静态↔运行时地址互译（按需懒加载 Ghidra 静态基址）

动态调试只依赖 gdb；Ghidra 仅在 gdb_map_address 中提供静态基址，
Ghidra 缺失不影响其余调试工具。
"""

from __future__ import annotations

import os

SESSION_PREFIX = "dbg-"

GDB_BRIDGE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "gdb_bridge.py"))
