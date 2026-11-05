# @category APRE
# -*- coding: utf-8 -*-
# @runtime Jython
u"""空操作脚本，仅用于首次 import 时占位（触发自动分析）。"""

from _common import emit_result

emit_result({"status": "imported", "program_name": currentProgram.getName()})
