# APRE 动态调试工作流参考（gdb_*）

本参考面向使用 APRE 的外部 Agent：何时启用动态调试、如何组织工具调用、
常见 CTF/逆向场景的处理方法。动态调试由独立的 **gdb 引擎** 提供（工具前缀 `gdb_`），
是可选能力：gdb 缺失时静态分析不受影响（见 check_engines 的 optional_missing_engines）。
工具 Schema 以 `tools/list` 为准。

## 何时使用动态调试

- 静态分析无法确定运行时行为：间接跳转、自修改代码、解密/解包逻辑、虚拟机保护。
- 需要观察真实数据流：加密前后数据、输入变换、比较目标（flag 校验）。
- 需要运行时 patch 绕过反调试/校验，或注入输入观察分支。
- 崩溃/异常现场：目标退出后会话保留寄存器与调用栈，可做 post-mortem 分析。

动态调试会**真实执行目标程序**，先确认环境与样本可信度，再决定是否运行。

## 前置条件

1. `check_engines`：确认 engines 中 gdb 条目的 `available=true`；
   读取 `gdb_path`、`python_version`、`ptrace_scope`（attach 能力）与 `attach_note`。
2. gdb 缺失时返回 `install_hint`（apt install gdb 或 `APRE_GDB` 指向自定义构建）；
   按 `agent_action` 处理，不要绕过环境检查。

## 基本会话流程

1. 创建会话：
   - `gdb_launch`：本地 ELF。`stop_at=entry`（程序入口，自动处理 PIE 重定位）、
     `main`（main 断点无法解析时，在运行前退回入口并给出 warnings）、`input`（首次 stdin read/readv 前）、`none`（直接运行）。
     可传 `args`、`env`、`cwd`。不推断 stripped 程序的 main 地址；检查 `effective_stop_at`
     确认初始化实际停点，`null` 表示未达到请求停点；`instruction` 表示仅确认首条指令停点。
   - `gdb_attach`：附加运行中进程（受 ptrace_scope 限制，失败诊断含原因）。
   - `gdb_connect`：远端 gdbserver/qemu（`host`/`port`），可选 `target_path` 载入本地符号。
2. 用返回的 `session_id` 做后续操作；`gdb_sessions` 随时查看会话状态与 gdb PID。
   检查 gdb_alive / inferior_alive / can_control；死亡会话自动归档，exited 默认保留输出，reap_exited=true 可关闭并归档。
3. 结束：`gdb_kill`（终止进程并清理）或 `gdb_detach`（放行进程）。

会话是独立 gdb 进程：工具调用之间、MCP 重启之间都保持存活；空闲超时
（`APRE_DEBUG_IDLE_TIMEOUT`，默认 3600s）后自动终止。会话初始化有看门狗
（`APRE_DEBUG_INIT_WATCHDOG`，默认 10s）：目标跑飞或阻塞等待输入时自动 SIGINT
打断并返回停止状态，`gdb_launch` 不会无限挂起（stop_at=entry 的非 PIE 与
stop_at=none 的长运行程序均受保护）。看门狗触发均返回 warnings；main 前的信号或退出
也会报告未命中 main，不重新运行目标。初始化 warnings 只在 launch 返回，历史保存在 session.json 的 startup_warnings；后续 gdb_state 保留 effective_stop_at，不重复警告。

## 静态 → 运行时地址换算（PIE/ASLR）

Ghidra 的地址是静态地址，gdb 需要运行时地址：

1. `ghidra_list_functions` 取目标函数的静态地址。
2. `gdb_map_address`（默认 direction=static_to_runtime）换算。
   - 静态基址来自 Ghidra（首次调用触发 analyzeHeadless，结果缓存于会话目录）；
   - 运行时基址来自 gdb 的 `/proc` 进程映射；`pie_detected=true` 表示目标为 PIE。
3. 换算结果用于 `gdb_breakpoint --location <runtime_addr>`、
   `gdb_step --action run_until --address <runtime_addr>` 等。
4. 反方向（runtime_to_static）用于把 gdb 的 PC/调用栈地址对应回 Ghidra 函数，
   再 `ghidra_decompile` 读伪代码。
5. 限制：只换算主模块；libc 等共享库不适用；远端目标无 `/proc` 映射时不可用。

非 PIE 且 gdb 默认关闭 ASLR 时，运行时地址与静态地址通常一致，可直接使用。

## 常用场景

### 停在关键点观察数据流

```
launch(stop_at=main)
  -> ghidra_list_functions（找可疑函数静态地址）
  -> gdb_map_address（换算）
  -> breakpoint set --location <runtime_addr>
  -> continue（停在断点；超时自动 SIGINT 并返回停止状态）
  -> registers / memory_read / backtrace / disassemble / evaluate
  -> step（单步跟进）或 run_until（跑到下个关键点）
```

### 交互式输入注入（pwn/菜单题）

程序等待输入时不能直接继续（会阻塞到超时中断）：

1. 推荐 `gdb_launch(stop_at=input)` 在 Linux x86/x86-64/AArch64 的首次 fd=0 read/readv 前停住。
   这不保证覆盖所有输入 API；检查 effective_stop_at。也可默认停在 entry 就预先输入，
   或手动在 scanf/fgets/read 入口下断点。
2. `gdb_send_input --data "payload\n"`：输入写入 PTY 缓冲区。
3. `continue`：程序恢复后读取该输入。
4. `gdb_output` 读取程序输出（提示符、回显、结果）。

注意：输入只能在停止状态写入；目标正在运行并阻塞等待输入时，先用
`gdb_interrupt` 停下再注入。

### 对抗反调试

- 定时器/闹钟：先确认目标是否依赖该信号。递送前停下用 `gdb_handle_signal --signal SIGALRM --stop --print --pass-to-program`；明确要抑制递送才用 `--no-stop --no-print --no-pass-to-program`。后者改变行为，不等于 alarm(0)。启动时也可选 alarm_policy=stop/ignore。
- fork 服务进程：`gdb_set --setting follow_fork_mode --value child`。
- ptrace 检测：`breakpoint set --type catch_syscall --location ptrace`，
  命中后看调用方（backtrace），必要时运行时 patch 绕过。
- 系统调用追踪：`breakpoint set --type catch_syscall`（全部）或指定名称。

### 运行时 patch 绕过校验

```
breakpoint set --location <比较点地址>
continue -> memory_write --address <跳转/比较指令地址> --bytes [0x90, 0x90, ...]
continue -> 观察行为；patch 只作用于进程内存，重启后失效
```

### 崩溃现场（post-mortem）

目标因 SIGSEGV 等信号**停止但尚未退出**时，可用 backtrace/registers/memory_read 读现场。
目标已经退出（state=exited）后，仅保留退出码、日志和输出；没有 core 文件时不能再读活进程栈或寄存器。
用 gdb_state/gdb_output 取回结果，reap_exited=true 关闭并归档。

### 观察/写内存

- `memory_read --address <addr>`：地址支持数字或 gdb 表达式（如 `$rsp`、`main+8`）。
- `memory_search --start <addr> --length <n> --pattern [0x..,...]`：定位数据/字符串。
- `evaluate --expression "*(char**)($rsp+8)"`：解引用；含函数调用的表达式会执行目标代码，慎用。

## 长操作与后台作业

首次 `ghidra_inspect`（大目标导入）、`gdb_launch` 等长操作应走作业层，避免
客户端请求超时后盲目重试：

```
job_submit(tool_name="ghidra_inspect", arguments={"target_path": ...}) -> job_id
job_status(job_id, wait=N)   # 轮询；running 含进度心跳，done 含完整 result（含 record_id）
job_list / job_remove        # 查看与清理；超 TTL 的已完成作业自动清理
```

作业 worker 是独立进程，提交者退出后继续执行；ghidra 作业的 job_status 返回
`log_hint`（最新 ghidra_logs 路径）可了解导入进度。

## 错误与诊断

- 任何失败都返回 `limitations`（未完成项、原因、不确定性）与结构化 `diagnostics`
  （code/severity/details/suggestions），并关联 `record_id`。
- 会话问题先看 `gdb_sessions`：`busy` 表示 continue/step 正在执行（用 `gdb_interrupt` 中断）；
  已消失的会话在 `reaped` 摘要中给出清理原因与 gdb_log_tail。
- attach 报 `ptrace: Operation not permitted` 是内核限制（yama ptrace_scope），
  不是工具故障；改用 launch 或调整内核参数（需授权）。
- continue 超时返回 `interrupted_after_timeout=true` 与停止状态：这是设计行为，
  不是失败；会话仍可用。

## 运行时内存同步到 Ghidra

先比较运行时与工程字节；确认存在差异且需要分析该快照时，
停住目标并调用 `ghidra_apply_memory(session_id, address, length)`。
halt_baddata 本身不确认差异，也不确认 SMC。软件断点可能改写并还原旧字节；
在会被修改/校验的区域考虑硬件断点或稳定的外围停止点。
address 是运行时地址或 GDB 表达式；默认自动换算主模块 PIE 地址、重建代码并增量分析。
随后用返回的 static_address 反编译。纯数据设 rebuild_code=false，目的地址另行指定时传 static_address。
快照与原始字节备份路径随结果返回；不会修改原始 ELF 或进程内存。代码范围必须正确，
多阶段解密及花指令不能保证自动恢复。旧调试会话无目标指纹时需重新创建。

启动/操作失败先看 diagnostics.details.snapshot 的 show cwd、info files、info program、
gdb_output_tail 和 inferior_output_tail，不要仅从 127 推断目标崩溃。cwd 传真实路径，勿额外加 shell 引号。
