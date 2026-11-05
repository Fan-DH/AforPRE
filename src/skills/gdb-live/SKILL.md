---
name: gdb-live
description: 使用 APRE/GDB 验证执行路径、输入输出、内存与静态地址映射
---

先调用 `check_engines` 检查 gdb 条目。静态分析通过不代表内核允许 ptrace；
launch/attach 的实际结果才确认调试权限。仅运行用户授权的目标。

`gdb_launch(stop_at=main)` 返回 `session_id`。检查 `state`、`stop`、`warnings`
和 `effective_stop_at`：stripped 程序无法解析 main 时退回入口，并不保证停在 main。
会话独立于 MCP 进程存活。`gdb_sessions` 可找回会话，勿因重连重复启动目标。

常用流程：`gdb_breakpoint` 设置断点 → `gdb_continue` → `gdb_state` / 寄存器 /
内存 / 调用栈。交互目标可用 `gdb_launch(stop_at=input)` 停在首次 stdin read/readv 前
（Linux x86/x86-64/AArch64）；或默认 entry 停点预先缓冲输入。用 `gdb_send_input`
写入文本（行输入包含 `\n`），再 continue。`gdb_output` 分批读取归档输出。
带函数调用的 `gdb_evaluate` 会执行目标代码，不能视为纯读取。
表达式直接写 `fun(3)`，不加 call/print；无类型符号需按正确 ABI 转换函数指针。
`x/40bx $rbp-0x30` 是命令，应使用 `gdb_memory_read(address="$rbp-0x30", length=40)`。
evaluate 超时会尝试中断并报告 timeout；副作用不回滚，先查状态，不自动重试调用。
软件断点（含临时断点）会改写指令；在自修改或完整性校验区域考虑 type=hardware
或稳定的外围停止点。硬件断点受槽位/目标支持限制，GDB 回读可能隐藏软件断点替换字节。

Ghidra 返回的静态地址先用 `gdb_map_address` 转换，再设置运行时地址断点
（location 形如 `*0x...`）；仅适用于主模块，不要混用 libc 或其他库地址。
结束时用 `gdb_kill` 终止目标与调试器；`gdb_detach` 会让目标继续运行。
详细流程见 `apre://skills/gdb-live/references/debug-workflow.md`。

初始化 warnings 只在 launch 返回，后续状态查询不重复。失败优先检查 diagnostics 中的 snapshot。
确认运行时与工程字节不同后，可调用 `ghidra_apply_memory(session_id, address, length)` 同步到 Ghidra，
再用返回的 static_address 反编译。纯数据设 rebuild_code=false；该工具不修改原始 ELF。


批量采集用 `gdb_trace`，默认最多 100 次单步、总计 10 秒；记录每次操作后的停止点。
指定 registers 可采集寄存器；memory_address + memory_length 可在每点保存二进制内存。
默认遇信号/断点停止；明确要继续 trap 采集时用 action=continue、continue_signals=["SIGTRAP"]，
部分 GDB 将 int3 上报为 unknown_stop；确认后可显式 continue_unknown_stops=true。
并先核对 gdb_handle_signal 的 pass_to_program（trace 不改变信号策略）。检查 termination 和 records，
preview 只有前三条，完整结果在返回的 JSONL 路径。不是完整 CPU 指令记录。
大块数据用 `gdb_memory_dump` 导出，返回 path/SHA-256/实际长度，单次上限 1 MiB。
两者的文件保存在服务端工作目录 artifacts 下，独立于会话生命周期。
MCP 默认 compact 保留风险诊断、隐藏固定说明；response_detail=full 查看完整返回。
完整历史始终可按 record_id 在工作目录 record.jsonl 查找，避免重做有副作用的操作。


裸 0x/十进制 software/hardware 断点会自动按地址解释；pending 会告警，不等于已可命中。
目标自己 ptrace 子进程时，不要盲目 detach_on_fork=off：可能与真正 tracer 冲突。
本地停止的 tracee 可用 gdb_tracee_read(pid, address, length)，必须确由当前 inferior 跟踪，
address 是子进程绝对地址。已保存 user_regs 缓冲区用 gdb_read_struct(address,
layout=linux_x86_64_user_regs)，来源/采集时效由调用者确认，不猜栈偏移。
动态导入定时器只是线索；启动 alarm_policy=stop 在 SIGALRM 递送前停下，ignore 会抑制递送，
改变程序行为且不等于 alarm(0)。不要把 pass_to_program=true 当作屏蔽信号。
gdb_sessions 区分 gdb_alive / inferior_alive / can_control；exited 不可继续执行，
reap_exited=true 可关闭并归档，默认保留最后输出。process_alive 只是 gdb_alive 的兼容别名。
compact 错误只显示 GDB 快照摘要，根因和 record_id 保留；完整诊断在历史记录中。
