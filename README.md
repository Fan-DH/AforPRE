# APRE 0.1.0

当前共 74 个工具：环境管理 1 个、后台作业 4 个、binutils 4 个、Ghidra 静态 22 个、gdb 动态调试 28 个、track 污点分析 15 个。

### Ghidra

| 工具 | 功能与其他参数 |
| --- | --- |
| `ghidra_batch` | 同一目标最多 16 项只读查询共用一次 JVM；逐项返回结果，失败项不丢失成功项 |
| `ghidra_inspect` | 程序概览、函数/字符串数、内存块 |
| `ghidra_list_functions` | 函数列表；可选 `name_filter`、`include_thunk`（默认 true） |
| `ghidra_list_globals` | 符号列表；可选 `name_filter`、`types`（默认 LABEL） |
| `ghidra_decompile` | C 伪代码；必需 `address` 或 `name`；可选 `timeout`（默认 60 秒） |
| `ghidra_xrefs_to` | 到指定地址的引用；必需 `address` |
| `ghidra_xrefs_from` | 函数的调用者/被调用者；必需 `address` 或 `name` |
| `ghidra_get_strings` | 已定义字符串；可选 `pattern`、`min_length` |
| `ghidra_read_bytes` | 字节、hex、ASCII；必需 `address`；可选 `length`（默认 16） |
| `ghidra_read_string` | 已定义字符串或原始 C 字符串；必需 `address`；可选 `max_length`（默认 256） |
| `ghidra_define_string` | 定义字符串；必需 `address`；可选 `string_type`（char/wchar/unicode） |
| `ghidra_get_cfg` | 函数基本块与前驱/后继；必需 `address` 或 `name` |
| `ghidra_get_call_graph` | 全程序调用边；可选 `address` 或 `name` 切换到单函数 |
| `ghidra_rename_symbol` | 重命名；必需 `address`、`new_name` |
| `ghidra_set_signature` | 返回类型/参数名；必需 `address`；可选 `return_type`、`param_names` |
| `ghidra_apply_memory` | GDB 停止态内存 → Ghidra 工程；必需 `session_id`、运行时 `address`、`length`；默认地址换算、代码重建和增量分析 |
| `ghidra_patch_bytes` | 项目内 patch；必需 `address`、`bytes`（非空 0-255 整数数组） |
| `ghidra_add_comment` | 注释；必需 `address`、`comment`；可选 `comment_type`（plate/pre/post/eol） |
| `ghidra_find_crypto` | AES/DES/MD5/SHA/TEA/CRC32/Blowfish/RC6/SM4 特征常量 |
| `ghidra_disassemble` | `mode=listing` 读取已有分析；`mode=linear` 从原始字节独立线性解码，不依赖函数、不修改工程；必需 `address`，`length` 默认 64、上限 65536 |
| `ghidra_create_function` | 按 address + length 完整线性解码、定义代码并创建函数；可选 name、replace_existing，控制流仍未验证 |
| `ghidra_reset_project` | 删除该目标的项目状态，下次重新导入 |

### GDB

| 工具 | 功能与其他参数 |
| --- | --- |
| `gdb_launch` | 创建调试会话并运行；可选 `args`、`env`、`cwd`、`stop_at`（entry/main/input/none） |
| `gdb_attach` | 附加到运行中的进程；必需 `pid`；可选 `target_path` 符号文件 |
| `gdb_connect` | 连接远端调试目标（gdbserver/qemu）；必需 `host`、`port`；可选 `target_path` |
| `gdb_sessions` | 分开报告 GDB/目标存活和 can_control；reap_exited=true 可关闭退出会话并归档 |
| `gdb_kill` | 终止会话（结束目标进程并清理会话目录） |
| `gdb_detach` | 分离：目标进程继续独立运行，会话结束 |
| `gdb_continue` | 继续执行到停止/退出；可选 `timeout`（超时自动 SIGINT 并返回停止状态） |
| `gdb_interrupt` | 向运行中的目标发送 SIGINT 并返回停止状态 |
| `gdb_step` | 单步；`action` 选 step/next（指令或源码级）、finish、run_until（需 `address`） |
| `gdb_trace` | 批量单步/停止点采集；`action`、`max_steps`、`timeout`、`registers`、可选 `memory_address` + `memory_length`；JSONL 和二进制文件 |
| `gdb_state` | 停止原因、信号、PC、当前函数、线程列表、退出码 |
| `gdb_output` | 读取目标进程的增量输出（PTY 捕获，交互提示可见） |
| `gdb_send_input` | 向目标 stdin 写入数据（停止状态下缓存，恢复后由程序读取） |
| `gdb_registers` | 读寄存器；可选 `names` 过滤、`all` 全量（含向量） |
| `gdb_read_struct` | 显式解码当前 inferior 保存的 linux_x86_64_user_regs 结构；需 address 和 layout，不依赖调试类型 |
| `gdb_tracee_read` | 读取当前 inferior 作为 tracer 时其已停止 tracee 的内存；需 pid、子进程绝对 address、length |
| `gdb_memory_read` | 运行时内存 hex+ascii；必需 `address`；可选 `length` |
| `gdb_memory_dump` | 停止态内存导出二进制；必需 `address`、`length`（1..1048576）；返回路径、SHA-256、停止点和断点上下文 |
| `gdb_memory_write` | 运行时 patch 内存；必需 `address`、`bytes`；返回回读校验 |
| `gdb_memory_search` | 按字节模式搜索内存；必需 `start`、`length`、`pattern`；可选 `max_hits` |
| `gdb_backtrace` | 调用栈帧（级别、PC、函数名）；可选 `depth` |
| `gdb_disassemble` | 运行时反汇编；可选 `address`（默认 PC）、`count` |
| `gdb_evaluate` | 求值表达式（$rax、解引用、算术；可调用函数，有副作用） |
| `gdb_breakpoint` | 断点管理：set（software/hardware/watch/catch）/remove/remove_all/list |
| `gdb_thread` | 线程列表与切换（list/select） |
| `gdb_set` | fork 跟随、调度锁、ASLR 等行为设置 |
| `gdb_handle_signal` | 信号处理策略（stop/print/pass，如对抗 SIGALRM 反调试） |
| `gdb_map_address` | Ghidra 静态地址与运行时地址互译（自动处理 PIE 基址偏移） |

### track

| 工具 | 功能与其他参数 |
| --- | --- |
| `track_run` | 有界 Pin 采集，可直接提供 stdin 或 TCP/UDP 重放；返回 trace_id、质量、重点位置与下一步建议 |
| `track_import` | 快照导入已有 JSONL、校验并建索引；allow_partial 显式允许残缺日志 |
| `track_summary` | 查看质量、输入及重点；省略 trace_id 列出最近轨迹，含取消后保留的产物 |
| `track_query` | 按类型与来源分页查询输入、输出字节溯源、事件、指令、标签、诊断及已观察控制流边 |
| `track_explain` | 按 seq 解释操作数来源、执行前值、地址依赖及代码坐标；支持 operand 缩小范围 |
| `track_influence` | 按 input_id、offset、length 定位受影响代码；区分 data/address/control/length |
| `track_compare` | 显式对应两次输入字节范围，比较影响位置和分支方向计数；附两份轨迹质量 |
| `track_export` | 导出完整原始轨迹或有界查询报告，返回路径、哈希与截断标志 |
| `track_slice` | 从事件操作数字节向后追溯候选写入链，识别常用寄存器别名/覆盖；报告缺口与预算，非精确切片 |
| `track_branches` | 条件与间接目标来源、实际分支方向及候选标志位写入的比较值 |
| `track_path` | 指定 tid 的有序已记录控制转移及重复后向转移候选，非完整 CFG/循环证明 |
| `track_memory` | 指定内存范围的读写、标签覆盖、数据来源与地址来源 |
| `track_values` | 指定指令的动态实例与执行前值；明确缺值和短读 |
| `track_compare_paths` | 显式指定两侧线程，对齐有界事件序列，定位分歧和带标签操作数值变化 |
| `track_map_address` | 用指令锚定模块，换算本次 Pin 运行与 ELF/Ghidra 地址；可读取真实 Ghidra 工程基址 |

### 其余工具

| 工具 | 功能与其他参数 |
| --- | --- |
| `check_engines` | 环境状态与安装指引，无参数 |
| `job_submit` | 后台作业：把任意工具调用交给独立 worker 异步执行，立即返回 job_id |
| `job_status` | 轮询作业状态/进度；wait 秒数内未完成返回当前进度；done 含完整 result（status 可能为 error） |
| `job_list` | 列出作业；worker 异常退出标记 failed，超过 TTL 的已完成作业自动清理 |
| `job_remove` | 取消并删除作业（终止运行中的 worker） |
| `inspect_target` | ELF 格式、架构、类型、入口与节表 |
| `search_strings` | 静态字符串；可选 `pattern`、`min_length` |
| `list_symbols` | 已定义符号，按地址排序 |
| `get_xrefs` | 启发式字符串引用；必需 `needle` |



## 程序运行

以下命令在仓库根目录执行。先检查环境：

```bash
python3 src/entrypoints/CLI/cli.py check_engines --json
```

### CLI：

```bash
python3 src/entrypoints/CLI/cli.py --help
python3 src/entrypoints/CLI/cli.py ghidra_decompile --help
```

### MCP：

```bash
python3 src/entrypoints/MCP/mcp_server.py
```

在客户端中注册 stdio server：

```json
{
  "mcpServers": {
    "apre": {
      "command": "python3",
      "args": [".../src/entrypoints/MCP/mcp_server.py"],
      "env": {
        "APRE_WORKSPACE": ".../work",
        "GHIDRA_HOME": "/opt/ghidra_11.2.1_PUBLIC",
        "JAVA_HOME": "/path/to/jdk-21"
      }
    }
  }
}
```

## 输出

```json
{
  "status": "ok",
  "data": {"symbols": [], "count": 0},
  "error": null,
  "limitations": [],
  "record_id": "rec-0123456789abcdef0123456789abcdef",
  "diagnostics": []
}
```

## Skill 资源


```text
src/skills/
  binutils-quick/SKILL.md
  ghidra-deep/SKILL.md
  gdb-live/SKILL.md
  gdb-live/references/debug-workflow.md
  track-taint/SKILL.md
  track-taint/references/workflow.md
  track-taint/references/advanced.md
  ctf-strategy/SKILL.md
```