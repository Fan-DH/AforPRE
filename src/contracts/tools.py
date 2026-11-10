"""工具清单：面向 Agent 的动作声明（name / description / inputSchema）。

工具名即引擎的操作名，调度层按此名路由到引擎实现。
注意：契约是跨引擎共享的，这里的清单表达的是「本项目支持哪些动作」，
不绑定 binutils 还是 ghidra。
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolContract:
    name: str
    description: str
    input_schema: dict


TOOL_CONTRACTS: list[ToolContract] = [
    # --- 环境管理 ---
    ToolContract(
        name="check_engines",
        description=(
            "分析前必须调用：检查当前 APRE 服务中实际 Provider 的运行态及依赖。"
            "只有 all_available=true 且 can_continue=true 才可继续；"
            "detected_all_available=true 仅表示安装探测通过。按 agent_action 和 instructions 处理，"
            "restart_server 时真正重启并确认 server_instance_id 已变化。"
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
    ),
    # --- 后台作业（跨引擎异步执行） ---
    ToolContract(
        name="ghidra_batch",
        description=(
            "对同一目标执行一批 Ghidra 只读查询，共用一次 worker 请求（或一次 headless 启动）。"
            "operations 中每项包含 tool_name 和 arguments（不含 target_path）。"
            "不支持修改、重置或嵌套 batch；子项参数错误不阻止合法项执行。任一查询失败时整体返回 error，data.results 保留所有单项结果和从 0 开始的 index。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "operations": {"type": "array", "minItems": 1, "maxItems": 16,
                    "items": {"type": "object", "additionalProperties": False,
                        "properties": {"tool_name": {"type": "string", "minLength": 1},
                                       "arguments": {"type": "object"}},
                        "required": ["tool_name", "arguments"]}},
            },
            "required": ["target_path", "operations"],
        },
    ),
    ToolContract(
        name="job_submit",
        description=(
            "提交后台作业：把非 job_* 工具调用交给独立 worker 异步执行并立即返回 job_id，"
            "用 job_status 轮询状态与最终结果。适用于首次 Ghidra 导入、调试会话启动等"
            "超过客户端请求超时的长操作；作业在提交者退出后继续执行，结果照常写入 Record。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "要异步执行的工具名，如 ghidra_inspect"},
                "arguments": {"type": "object", "description": "该工具的完整参数对象，如 {\"target_path\": \"/path\"}"},
            },
            "required": ["tool_name", "arguments"],
        },
    ),
    ToolContract(
        name="job_status",
        description=(
            "查询后台作业：state=running/done/failed、进度心跳、耗时。done 表示作业执行完毕，"
            "result 与同步调用同构（含 record_id），但其 status 可能为 error（工具本身失败）；"
            "failed 表示 worker 进程异常退出。wait 为等待完成的最大秒数（默认 0=立即返回）。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "job_submit 返回的作业 ID"},
                "wait": {"type": "integer", "description": "最多等待秒数，0–30，默认 0=立即返回"},
            },
            "required": ["job_id"],
        },
    ),
    ToolContract(
        name="job_list",
        description=(
            "列出全部作业（状态、耗时、worker PID）。worker 异常退出的 running 作业会被标记"
            "为 failed；已完成超过 APRE_JOB_TTL（默认 3600s）的作业自动清理（摘要见 reaped）。"
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
    ),
    ToolContract(
        name="job_remove",
        description="取消并删除作业：停止运行中的 worker 及其子进程组，清理作业目录；已执行的修改不自动回滚。已完成作业创建的 GDB 会话用 gdb_kill 管理。",
        input_schema={
            "type": "object",
            "properties": {"job_id": {"type": "string"}},
            "required": ["job_id"],
        },
    ),
    ToolContract(
        name="inspect_target",
        description="检查 ELF 文件概览：格式（ELF32/64）、架构、类型、入口点与节表。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "ELF 文件的绝对或相对路径"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="search_strings",
        description="提取并筛选 ELF 中的可打印静态字符串；pattern 是正则，忽略大小写。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "pattern": {"type": "string", "description": "可选正则，例如 flag"},
                "min_length": {"type": "integer", "description": "最小字符串长度，默认 4"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="list_symbols",
        description="列出已定义符号（按地址排序），用于定位函数与全局对象。",
        input_schema={
            "type": "object",
            "properties": {"target_path": {"type": "string"}},
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="get_xrefs",
        description="查询字符串的直接代码引用、自然对齐绝对数据指针候选及经指针的一跳引用。返回 kind、覆盖范围与截断标志；不覆盖全部运行时/重定位/编码指针。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "needle": {"type": "string", "description": "要查找引用的字符串内容"},
            },
            "required": ["target_path", "needle"],
        },
    ),
    # --- Ghidra 引擎工具 ---
    ToolContract(
        name="ghidra_inspect",
        description="用 Ghidra 解析程序概览：架构、编译器、入口点、函数数、字符串数、内存块。",
        input_schema={
            "type": "object",
            "properties": {"target_path": {"type": "string"}},
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="ghidra_list_functions",
        description="列出 Ghidra 识别的所有函数（地址、名、大小、签名、是否 thunk）。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "name_filter": {"type": "string", "description": "可选正则，过滤函数名"},
                "include_thunk": {"type": "boolean", "description": "是否包含 thunk 函数，默认 true"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="ghidra_list_globals",
        description="列出全局符号（非函数的标签/数据符号）。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "name_filter": {"type": "string", "description": "可选正则，过滤符号名"},
                "types": {"type": "array", "items": {"type": "string"},
                          "description": "符号类型过滤，默认 [\"LABEL\"]"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="ghidra_decompile",
        description="反编译指定函数为 C 伪代码（Ghidra Decompiler）。需提供 address 或 name。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string", "description": "函数入口地址（如 0x401000）"},
                "name": {"type": "string", "description": "函数名（当 address 未提供时按名查找）"},
                "timeout": {"type": "integer", "description": "反编译超时秒，默认 60"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="ghidra_xrefs_to",
        description="查找对某地址的所有引用（含引用类型：读/写/调用，及所在函数）。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string", "description": "目标地址"},
            },
            "required": ["target_path", "address"],
        },
    ),
    ToolContract(
        name="ghidra_xrefs_from",
        description="查找某函数调用了哪些函数（callees）以及被谁调用（callers）。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string", "description": "函数入口地址"},
                "name": {"type": "string", "description": "函数名"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="ghidra_get_strings",
        description="用 Ghidra 提取已定义字符串（带地址、长度、字符集）。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "pattern": {"type": "string", "description": "可选正则，过滤字符串内容"},
                "min_length": {"type": "integer", "description": "最小字符串长度，默认 4"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="ghidra_read_bytes",
        description="读取某地址处的字节（hex + ascii dump）。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string"},
                "length": {"type": "integer", "description": "读取字节数，默认 16"},
            },
            "required": ["target_path", "address"],
        },
    ),
    ToolContract(
        name="ghidra_read_string",
        description="读取某地址处的字符串（优先读已定义数据，否则按 C 字符串读取）。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string"},
                "max_length": {"type": "integer", "description": "按 C 字符串读取时的最大长度，默认 256"},
            },
            "required": ["target_path", "address"],
        },
    ),
    ToolContract(
        name="ghidra_define_string",
        description="在某地址定义字符串（修改类操作，持久化到 project）。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string"},
                "string_type": {"type": "string", "description": "char/wchar/unicode，默认 char"},
            },
            "required": ["target_path", "address"],
        },
    ),
    ToolContract(
        name="ghidra_get_cfg",
        description="获取函数的控制流图（基本块 + 前驱/后继边）。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string"},
                "name": {"type": "string"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="ghidra_get_call_graph",
        description="获取调用图。无 address/name 时返回全程序调用边。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string"},
                "name": {"type": "string"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="ghidra_rename_symbol",
        description="重命名符号（函数或一般符号）。修改类操作，持久化到 project。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string"},
                "new_name": {"type": "string"},
            },
            "required": ["target_path", "address", "new_name"],
        },
    ),
    ToolContract(
        name="ghidra_set_signature",
        description="设置函数返回类型与参数名。修改类操作。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string"},
                "return_type": {"type": "string", "description": "返回类型，如 int/char*/void"},
                "param_names": {"type": "array", "items": {"type": "string"},
                                "description": "参数名列表"},
            },
            "required": ["target_path", "address"],
        },
    ),
    ToolContract(
        name="ghidra_apply_memory",
        description=("把停止中的 GDB 会话内存快照写入对应 Ghidra 工程，用于已确认的运行时/工程字节差异。"
                     "address 为运行时地址或 GDB 表达式；默认自动换算主模块地址。"
                     "static_address 可显式指定已存在的 Ghidra 内存区。默认重建代码并增量分析；"
                     "代码起点应为真实指令边界，纯数据请设置 rebuild_code=false。原始文件不变。"),
        input_schema={"type": "object", "properties": {
            "session_id": {"type": "string"},
            "address": {"type": "string"},
            "length": {"type": "integer", "maximum": 1048576},
            "static_address": {"type": "string", "description": "可选：Ghidra 十六进制目的地址"},
            "rebuild_code": {"type": "boolean", "description": "默认 true，清除旧代码/数据定义，从目的地址重建指令"},
            "reanalyze": {"type": "boolean", "description": "默认 true，重新分析受影响内容"},
        }, "required": ["session_id", "address", "length"]},
    ),
    ToolContract(
        name="ghidra_patch_bytes",
        description="修改字节（patch）。修改类操作，持久化到 project。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string"},
                "bytes": {"type": "array", "items": {"type": "integer"},
                          "description": "要写入的字节列表（0-255）"},
            },
            "required": ["target_path", "address", "bytes"],
        },
    ),
    ToolContract(
        name="ghidra_add_comment",
        description="添加注释。修改类操作。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string"},
                "comment": {"type": "string"},
                "comment_type": {"type": "string", "description": "plate/pre/post/eol，默认 eol"},
            },
            "required": ["target_path", "address", "comment"],
        },
    ),
    ToolContract(
        name="ghidra_find_crypto",
        description="扫描加密算法特征常量（AES/DES/MD5/SHA/TEA/CRC32/Blowfish/RC6/SM4 等）。",
        input_schema={
            "type": "object",
            "properties": {"target_path": {"type": "string"}},
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="ghidra_disassemble",
        description="按地址范围读取 listing，或用 mode=linear 独立线性解码原始字节（不依赖函数、不修改工程、不追踪跳转）。",
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "address": {"type": "string"},
                "length": {"type": "integer", "maximum": 65536, "description": "范围字节数，默认 64，末端不包含"},
                "mode": {"type": "string", "enum": ["listing", "linear"]},
            },
            "required": ["target_path", "address"],
        },
    ),
    ToolContract(
        name="ghidra_reset_project",
        description="重置 Ghidra project（清空分析与修改状态），下次操作时重新导入分析。",
        input_schema={
            "type": "object",
            "properties": {"target_path": {"type": "string"}},
            "required": ["target_path"],
        },
    ),
    # --- gdb 动态调试工具 ---
    ToolContract(
        name="gdb_launch",
        description=(
            "启动动态调试会话：按 stop_at 停在入口/主函数/首次 stdin 读取前或直接运行。"
            "调试前必须先调用 check_engines 确认环境。会话在 MCP 服务进程之外以独立 gdb 进程存在，"
            "工具调用之间状态保留；session_id 用于后续所有调试操作。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "待调试的 ELF 文件路径"},
                "args": {"type": "array", "items": {"type": "string"},
                         "description": "传给目标程序的命令行参数，默认空"},
                "env": {"type": "object", "description": "为目标程序追加的环境变量（KEY: VALUE），默认空"},
                "cwd": {"type": "string", "description": "目标程序的工作目录，默认继承服务进程"},
                "alarm_policy": {"type": "string", "enum": ["default", "stop", "ignore"],
                    "description": "SIGALRM 策略：默认保持 GDB 默认；stop=递送前停止；ignore=不递送（改变目标行为，不等于 alarm(0)，不处理其他定时器信号）"},
                "stop_at": {"type": "string", "enum": ["entry", "main", "input", "none"],
                            "description": "entry=停在程序入口指令（自动处理 PIE 重定位）；main=停在 main（无法解析时在运行前退回入口并给出 warnings）；input=在 Linux x86/x86-64/AArch64 的第一次 stdin read/readv 前停止，再 send_input 后 continue；none=直接运行，阻塞时初始化看门狗会中断。默认 entry。返回 effective_stop_at 表示初始化实际达到的停点策略，null 表示未达到"},
            },
            "required": ["target_path"],
        },
    ),
    ToolContract(
        name="gdb_attach",
        description="创建调试会话并附加到正在运行的进程 pid。受内核 ptrace 权限约束（yama ptrace_scope）。",
        input_schema={
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "目标进程 PID"},
                "target_path": {"type": "string",
                                "description": "可选：本地符号文件（与运行程序同版本），用于加载符号"},
            },
            "required": ["pid"],
        },
    ),
    ToolContract(
        name="gdb_connect",
        description="创建调试会话并连接远程调试目标（gdbserver / qemu 等，协议 gdb remote serial）。",
        input_schema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "远端主机名或 IP"},
                "port": {"type": "integer", "description": "远端调试端口"},
                "target_path": {"type": "string",
                                "description": "可选：本地二进制副本，用于加载符号"},
            },
            "required": ["host", "port"],
        },
    ),
    ToolContract(
        name="gdb_sessions",
        description=(
            "列出调试会话：会话 ID、目标、模式、状态、gdb 进程 PID、日志路径。"
            "分别返回 gdb_alive、inferior_alive、can_control。exited 保留输出且不可执行；reap_exited=true 关闭并归档。死亡会话自动归档，摘要见 reaped。"
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
    ),
    ToolContract(
        name="gdb_kill",
        description="终止调试会话：结束被调试进程（若仍在运行）并清理会话目录。会话终止后状态不可再查询。",
        input_schema={
            "type": "object",
            "properties": {"session_id": {"type": "string", "description": "会话 ID，如 dbg-xxxx"}},
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_detach",
        description="从被调试进程分离：目标进程继续独立运行，调试会话结束并清理。",
        input_schema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_continue",
        description=(
            "继续执行直到停止（断点/信号/退出/超时）。timeout 秒内未停止则自动中断并返回停止状态，"
            "不会终结会话；返回结果包含停止原因、PC 和期间产生的目标输出。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "timeout": {"type": "integer", "description": "等待停止的秒数，默认取 APRE_DEBUG_CONTINUE_TIMEOUT（默认 10）"},
            },
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_interrupt",
        description="异步中断正在运行的目标进程（向 gdb 进程组发送 SIGINT），随后返回当前停止状态。",
        input_schema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_step",
        description=(
            "单步执行：step_instruction/next_instruction=汇编级进入/越过；step_line/next_line=源码级进入/越过；"
            "finish=执行到当前函数返回；run_until=临时断点并运行到指定地址（需 address）。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "action": {"type": "string",
                           "enum": ["step_instruction", "next_instruction", "step_line",
                                    "next_line", "finish", "run_until"],
                           "description": "默认 step_instruction"},
                "address": {"type": "string", "description": "run_until 的目标地址（运行时地址或符号）"},
            },
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_state",
        description="读取会话当前状态：运行/停止/退出、停止原因、信号、PC、当前函数、线程列表、退出码。",
        input_schema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_send_input",
        description=(
            "向被调试进程的标准输入写入数据（仅停止状态下生效，数据缓存在 PTY 中，"
            "程序恢复执行后读取）。用于交互式程序的输入注入。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "data": {"type": "string", "description": "要写入的输入内容，如 \"1\\nflag\\n\""},
            },
            "required": ["session_id", "data"],
        },
    ),
    ToolContract(
        name="gdb_output",
        description="读取自上次读取以来被调试进程产生的标准输出/错误（经 PTY 捕获，含提示符等交互输出）。",
        input_schema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_registers",
        description="读取寄存器。names 为空时读取通用寄存器；all=true 读取全部（含向量/浮点）；也可按名过滤。",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "names": {"type": "array", "items": {"type": "string"},
                          "description": "寄存器名列表，如 [rax, rip, rsp]，默认空=通用寄存器"},
                "all": {"type": "boolean", "description": "读取全部寄存器（含向量），默认 false"},
            },
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_memory_read",
        description="读取被调试进程的运行时内存：hex + ascii 转储。",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "address": {"type": "string", "description": "运行时地址或 GDB 表达式，如 $rbp-0x30"},
                "length": {"type": "integer", "description": "读取字节数，默认 16"},
            },
            "required": ["session_id", "address"],
        },
    ),
    ToolContract(
        name="gdb_memory_write",
        description="向被调试进程的运行时内存写入字节（运行时 patch，不修改磁盘文件）。返回回读校验结果。",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "address": {"type": "string"},
                "bytes": {"type": "array", "items": {"type": "integer"},
                          "description": "写入的字节（0-255）"},
            },
            "required": ["session_id", "address", "bytes"],
        },
    ),
    ToolContract(
        name="gdb_memory_search",
        description="在运行时内存范围内搜索字节模式，返回命中地址列表。",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "start": {"type": "string", "description": "搜索起始地址"},
                "length": {"type": "integer", "description": "搜索范围字节数"},
                "pattern": {"type": "array", "items": {"type": "integer"},
                            "description": "要搜索的字节模式（0-255）"},
                "max_hits": {"type": "integer", "description": "最多返回命中数，默认 100"},
            },
            "required": ["session_id", "start", "length", "pattern"],
        },
    ),
    ToolContract(
        name="gdb_backtrace",
        description="读取调用栈：帧级别、PC、函数名（无符号时为空）。",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "depth": {"type": "integer", "description": "最大帧数，默认 20"},
            },
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_disassemble",
        description="反汇编被调试进程的运行时内存（address 缺省为当前 PC）。",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "address": {"type": "string", "description": "起始运行时地址，默认当前 PC"},
                "count": {"type": "integer", "description": "指令条数，默认 16"},
            },
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_evaluate",
        description=(
            "在停止状态下求值 C 风格表达式（如 $rax、*(char**)($rsp+8)、main+0x10）。"
            "仅接受表达式，不接受 x/print/call 命令；内存转储用 gdb_memory_read。"
            "支持 fn(args) 或 ((int (*)(int))0xADDRESS)(3) 等函数调用，类型须符合目标 ABI，"
            "会在目标进程内执行代码并产生副作用。超时自动中断，不回滚副作用。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "expression": {"type": "string"},
                "timeout": {"type": "integer", "description": "求值等待秒数，默认 APRE_DEBUG_RPC_TIMEOUT；超时中断，不自动重试"},
            },
            "required": ["session_id", "expression"],
        },
    ),
    ToolContract(
        name="gdb_breakpoint",
        description=(
            "断点管理。set：software/hardware 断点用 location 指定地址或符号；watch_read/write/access 用 location "
            "指定监视表达式（如 *(int*)0x404040）；catch_syscall/catch_signal 用 location 指定系统调用名或信号名"
            "（留空=全部系统调用）。remove 按 number 或 location 删除；remove_all 清除全部；list 列出全部。"
            "software 会改写指令，可能干扰自修改/完整性校验；此类位置可选 hardware（受目标支持和槽位限制）。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "action": {"type": "string", "enum": ["set", "remove", "remove_all", "list"],
                           "description": "默认 list"},
                "location": {"type": "string", "description": "software/hardware 的 0x 十六进制或纯十进制位置自动按地址解析；符号保持 GDB 语法；watch/catch 保持原义"},
                "type": {"type": "string",
                         "enum": ["software", "hardware", "watch_read", "watch_write",
                                  "watch_access", "catch_syscall", "catch_signal"],
                         "description": "默认 software"},
                "condition": {"type": "string", "description": "可选断点条件（gdb 条件语法）"},
                "temporary": {"type": "boolean", "description": "一次性断点，命中后自动删除，默认 false"},
                "number": {"type": "integer", "description": "remove 时按断点编号删除"},
            },
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_thread",
        description="线程管理：list=列出全部线程；select=切换当前线程（thread_id）。",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "action": {"type": "string", "enum": ["list", "select"], "description": "默认 list"},
                "thread_id": {"type": "integer", "description": "select 时的 gdb 线程编号"},
            },
            "required": ["session_id"],
        },
    ),
    ToolContract(
        name="gdb_set",
        description="调整调试器行为设置（fork 跟随、线程调度锁定、ASLR 等），返回设置后的当前值。",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "setting": {"type": "string",
                            "enum": ["follow_fork_mode", "follow_exec_mode", "scheduler_locking",
                                     "detach_on_fork", "stop_on_solib_events", "disable_randomization"]},
                "value": {"type": "string", "description": "取值见各设置：parent/child、same/new、off/on/step/replay、on/off、0/1、on/off"},
            },
            "required": ["session_id", "setting", "value"],
        },
    ),
    ToolContract(
        name="gdb_handle_signal",
        description="配置信号停止/递送策略。pass_to_program=false 才是不递送；true 仍会执行目标处理器。抑制信号会改变目标行为，不等于取消定时器。",
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "signal": {"type": "string", "description": "信号名，如 SIGALRM、SIGSEGV"},
                "stop": {"type": "boolean", "description": "收到信号时是否停下，默认 false"},
                "print": {"type": "boolean", "description": "收到信号时是否打印，默认 false"},
                "pass_to_program": {"type": "boolean", "description": "是否把信号传递给程序，默认 true"},
            },
            "required": ["session_id", "signal"],
        },
    ),
    ToolContract(
        name="gdb_map_address",
        description=(
            "在 Ghidra 静态地址与运行时地址之间换算（自动处理 PIE/ASLR 基址偏移）。"
            "静态基址取自 Ghidra 分析结果，运行时基址取自已加载的模块映射；"
            "远端调试目标无法读取进程映射时会失败。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "address": {"type": "string", "description": "待换算的地址"},
                "direction": {"type": "string",
                              "enum": ["static_to_runtime", "runtime_to_static"],
                              "description": "默认 static_to_runtime"},
            },
            "required": ["session_id", "address"],
        },
    ),
]

TOOL_CONTRACTS.extend([
    ToolContract("gdb_memory_dump", "将停止进程的内存导出为工作目录中的二进制文件，返回路径、长度和 SHA-256；不返回大段 hex。",
        {"type": "object", "properties": {
            "session_id": {"type": "string"}, "address": {"type": "string"},
            "length": {"type": "integer", "maximum": 1048576}},
         "required": ["session_id", "address", "length"]}),
    ToolContract("gdb_trace", "有界批量跟踪：每次单步或 continue 停止后记录 PC、停止原因、指定寄存器和可选内存。完整记录写 JSONL，内存另存二进制。默认遇信号/断点停止；continue 模式可显式允许指定信号及断点后继续。不会更改信号传递策略。",
        {"type": "object", "properties": {
            "session_id": {"type": "string"},
            "action": {"type": "string", "enum": ["step_instruction", "next_instruction", "continue"]},
            "max_steps": {"type": "integer", "maximum": 10000, "description": "执行次数上限，默认 100"},
            "timeout": {"type": "integer", "maximum": 300, "description": "整个跟踪的秒数上限，默认 10"},
            "registers": {"type": "array", "maxItems": 32, "items": {"type": "string", "minLength": 1}},
            "memory_address": {"type": "string", "description": "每次停止时求值，如 $rsp"},
            "memory_length": {"type": "integer", "maximum": 4096},
            "continue_signals": {"type": "array", "maxItems": 32, "items": {"type": "string", "minLength": 1}},
            "continue_unknown_stops": {"type": "boolean", "description": "默认 false；GDB 可能将 int3 报为普通 StopEvent，明确允许记录未知停止点后继续时设 true"},
            "continue_breakpoints": {"type": "boolean", "description": "默认 false；true 时记录断点后继续"}},
         "required": ["session_id"]}),
])

for _item in TOOL_CONTRACTS:
    if _item.name == 'gdb_sessions':
        _item.input_schema['properties']['reap_exited'] = {'type': 'boolean', 'description': '默认 false，保留退出会话输出；true 关闭已确认退出且无存活 inferior 的会话并归档日志'}
    if _item.name == 'get_xrefs':
        _item.input_schema['properties']['max_results'] = {'type': 'integer', 'maximum': 10000, 'description': '最多返回条数，默认 1000；扫描对齐的静态绝对数据指针和一跳代码引用'}

TOOL_CONTRACTS.extend([
    ToolContract('gdb_tracee_read', '只读读取当前 inferior 所跟踪的本地 Linux 子进程内存。校验 /proc TracerPid 和停止状态；不 attach，不调用目标函数，权限不足会报错。address 必须是子进程绝对地址。',
        {'type': 'object', 'properties': {'session_id': {'type': 'string'}, 'pid': {'type': 'integer'},
            'address': {'type': 'string'}, 'length': {'type': 'integer', 'maximum': 65536}},
         'required': ['session_id', 'pid', 'address', 'length']}),
    ToolContract('gdb_read_struct', '按显式 ABI 解码当前 inferior 中已保存的结构体，不依赖调试符号。不获取子进程实时寄存器；address 由调用者根据实际 ptrace 输出缓冲区确定，不能假定固定 rbp 偏移。',
        {'type': 'object', 'properties': {'session_id': {'type': 'string'}, 'address': {'type': 'string'},
            'layout': {'type': 'string', 'enum': ['linux_x86_64_user_regs']}},
         'required': ['session_id', 'address', 'layout']}),
    ToolContract('ghidra_create_function', '将显式地址范围线性定义为代码并创建函数，保存到 Ghidra 工程。先完整解码验证边界；默认拒绝覆盖已有函数，replace_existing=true 仅替换完全包含在范围内的函数。不会改 ELF，不能证明控制流正确。',
        {'type': 'object', 'properties': {'target_path': {'type': 'string'}, 'address': {'type': 'string'},
            'length': {'type': 'integer', 'maximum': 65536}, 'name': {'type': 'string'},
            'replace_existing': {'type': 'boolean'}}, 'required': ['target_path', 'address', 'length']}),
])

from contracts.track import contracts as _track_contracts
TOOL_CONTRACTS.extend(_track_contracts(ToolContract))

# Keep constraints next to the tool list so CLI and MCP share one contract.
_FUNCTION_SELECTORS = {
    "ghidra_decompile", "ghidra_xrefs_from", "ghidra_get_cfg",
}
for _contract in TOOL_CONTRACTS:
    _schema = _contract.input_schema
    _schema["properties"]["response_detail"] = {"type": "string", "enum": ["compact", "full"],
        "description": "MCP 默认 compact；full 返回完整诊断。完整结果始终保存在 record.jsonl。"}
    _schema["additionalProperties"] = False
    for _key, _spec in _schema["properties"].items():
        if _spec["type"] == "string" and _key not in {"pattern", "comment"}:
            _spec.setdefault("minLength", 1)
        if _spec["type"] == "integer":
            _spec.setdefault("minimum", 1)
    if _contract.name in _FUNCTION_SELECTORS:
        _schema["anyOf"] = [
            {"required": ["address"]}, {"required": ["name"]},
        ]
    if "string_type" in _schema["properties"]:
        _schema["properties"]["string_type"]["enum"] = ["char", "wchar", "unicode"]
    if "comment_type" in _schema["properties"]:
        _schema["properties"]["comment_type"]["enum"] = ["plate", "pre", "post", "eol"]
    if "bytes" in _schema["properties"]:
        _schema["properties"]["bytes"].update(
            minItems=1, items={"type": "integer", "minimum": 0, "maximum": 255},
        )
    if "param_names" in _schema["properties"]:
        _schema["properties"]["param_names"]["items"]["minLength"] = 1
    if "pattern" in _schema["properties"] and _schema["properties"]["pattern"]["type"] == "array":
        _schema["properties"]["pattern"].update(
            minItems=1, items={"type": "integer", "minimum": 0, "maximum": 255},
        )
    if "args" in _schema["properties"]:
        _schema["properties"]["args"].update(minItems=0)
    if _contract.name == "job_status":
        _schema["properties"]["wait"].update(minimum=0, maximum=30)

_BY_NAME = {contract.name: contract for contract in TOOL_CONTRACTS}


def get_tool_contract(name: str) -> ToolContract | None:
    return _BY_NAME.get(name) if isinstance(name, str) else None


def validate_arguments(contract: ToolContract, args: dict) -> None:
    """Validate the JSON Schema subset used by APRE, without dependencies."""
    if not isinstance(args, dict):
        raise ValueError("arguments 必须是对象")
    schema = contract.input_schema
    for key in schema.get("required", []):
        if key not in args:
            raise ValueError(f"缺少参数: {key}")
    unknown = args.keys() - schema["properties"].keys()
    if unknown:
        raise ValueError(f"未知参数: {', '.join(sorted(map(str, unknown)))}")
    if "anyOf" in schema and not any(
        all(key in args for key in choice["required"]) for choice in schema["anyOf"]
    ):
        raise ValueError("需提供 address 或 name")

    def check(value, spec, label):
        kind = spec["type"]
        valid = {
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
            "array": isinstance(value, list),
            "object": isinstance(value, dict),
        }[kind]
        if not valid:
            raise ValueError(f"{label} 必须是 {kind}")
        if kind == "string" and len(value) < spec.get("minLength", 0):
            raise ValueError(f"{label} 不能为空")
        if kind == "integer":
            if "minimum" in spec and value < spec["minimum"]:
                raise ValueError(f"{label} 不得小于 {spec['minimum']}")
            if "maximum" in spec and value > spec["maximum"]:
                raise ValueError(f"{label} 不得大于 {spec['maximum']}")
        if "enum" in spec and value not in spec["enum"]:
            raise ValueError(f"{label} 必须是 {spec['enum']} 之一")
        if kind == "array":
            if len(value) < spec.get("minItems", 0):
                raise ValueError(f"{label} 不能为空")
            if "maxItems" in spec and len(value) > spec["maxItems"]:
                raise ValueError(f"{label} 最多允许 {spec['maxItems']} 项")
            for index, item in enumerate(value):
                check(item, spec["items"], f"{label}[{index}]")
        if kind == "object" and "properties" in spec:
            try:
                validate_arguments(ToolContract(label, "", spec), value)
            except ValueError as exc:
                raise ValueError(f"{label}: {exc}") from exc

    for key, value in args.items():
        check(value, schema["properties"][key], key)
        if key in {"pattern", "name_filter"} and isinstance(value, str):
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"{key} 不是合法正则: {exc}") from exc
