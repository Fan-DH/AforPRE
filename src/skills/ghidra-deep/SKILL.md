---
name: ghidra-deep
description: 使用 APRE/Ghidra 反编译、追踪引用并验证项目修改
---

先调用 `check_engines`，检查 ghidra 的 `available`、依赖和诊断。
首次导入可能较慢：用 `job_submit` 提交 `ghidra_inspect`，再用 `job_status`
查询（`wait=0` 立即返回，最多等待 30 秒）。`state=done` 仅说明作业结束，
还需检查 `result.status`。不要因客户端等待超时重复提交修改操作。
同一目标的多个只读查询可用 `ghidra_batch` 合并（最多 16 项），共用一次 JVM 启动。
每项是 `{"tool_name":"ghidra_decompile","arguments":{"name":"main"}}`，
目标路径只在外层提供。部分查询失败时，成功项仍保存在 `data.results`。

从 `ghidra_list_functions` 的实际地址和名字选择函数，再调用 `ghidra_decompile`。
用 `ghidra_get_strings` → `ghidra_xrefs_to` 查字符串使用位置；用
`ghidra_xrefs_from`、`ghidra_get_cfg`、`ghidra_get_call_graph` 验证调用与分支。
Ghidra 地址字符串为十六进制，可能没有 `0x`，可直接传给同引擎工具和
`gdb_map_address`。`ghidra_disassemble.length` 是字节数，GDB 的 `count` 才是指令数。

反编译输出是推断的 C 代码。检查 `quality`、`limitations`、`diagnostics`；
`halt_baddata`、缺失函数或空引用列表均不能证明目标无行为。
修改工具只持久化到按目标内容 hash 保存的 Ghidra 项目，不修改原始 ELF。
重命名/签名修改后重新反编译核对；patch 后用 `ghidra_read_bytes` 回读。
数据区 patch 不应变成指令；代码 patch 后完整分析可能过期。
`ghidra_reset_project` 会删除该目标的项目修改，仅在确需重新分析时调用。

默认按工程复用常驻 Ghidra worker，连续调用不重复启动 JVM；空闲退出后下一次冷启动。
用 diagnostics 的 imported_this_call 和 worker_reused 区分导入、启动和复用。
batch 的错误项包含 index（从 0 开始）和 tool_name，参数错误不影响其他合法项。

Instruction overlaps、halt_baddata 或垃圾调用目标不能确定根因。先核对字节、
指令/函数边界、语言/基址及 patch 范围，不能仅凭告警推断加密、自修改或解包。
若已通过比较确认运行时字节与工程不同，且需要分析该时刻快照，
停住 GDB，调用 `ghidra_apply_memory(session_id, address, length)`，
使用返回的 static_address 重新反编译。默认清除旧定义、重建代码并增量分析，
纯数据设置 rebuild_code=false；检查 redisassembly_complete、analysis_complete 与 quality。
analysis_status 区分 not_requested 与 incomplete；function_rebuild_results 中 unchanged 不是失败。
quality.complete 在发现 halt_baddata / WARNING / trap intrinsic 时为 false，否则为 null（未知），不能保证语义正确或工程分析最新。
合法 int3 不必标 invalid_instruction=true；检查 trap_intrinsics、completeness 和控制流诊断。
函数识别缺失或被 trap 切碎时，用 ghidra_disassemble(mode=linear, address=..., length=...)
独立按物理地址解码已知范围；不修改工程，不恢复异常处理器控制流。检查 complete/termination/decoded_length。
同步长度必须覆盖实际所需范围；自动分析不会补回缺失的运行时字节。


确认显式边界后，可用 ghidra_create_function(address, length, name) 将线性范围定义为代码和函数。
默认拒绝覆盖已有函数；replace_existing=true 仅允许替换范围内完整函数，跨边界仍拒绝。
成功只意味着定义已保存，control_flow_verified=false；不能把可 decompile 等同于语义恢复完整。
