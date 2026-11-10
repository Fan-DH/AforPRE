"""Track schemas only; no engine imports or execution at contract discovery."""


def string(description="", **extra):
    return {"type": "string", "description": description, **extra}


def integer(description="", minimum=0, maximum=2147483647):
    return {"type": "integer", "minimum": minimum, "maximum": maximum, "description": description}


def obj(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


PAGE = {"cursor": integer("从返回的 next_cursor 继续；默认 0"),
        "limit": integer("默认 20，最多 100；输出另有字节预算", 1, 100)}
TRACE = {"trace_id": string("track_run / track_import 返回的轨迹 ID")}
SOURCE = {"input_id": integer("一次成功读取的编号，不是报文编号", 1),
          "offset": integer("输入内起始字节，默认 0"),
          "length": integer("输入字节范围长度，默认 1", 1, 1048576)}
FILTERS = {
    "tid": integer("线程 ID，允许 0"), "seq_start": integer("起始事件序号", 1),
    "seq_end": integer("末事件序号，包含边界", 1),
    "instruction_id": integer("轨迹内静态指令 ID", 1),
    "image": string("镜像路径子串"), "routine": string("Pin 符号提示子串；stripped/IFUNC 库可能不是真实函数名，优先 image+offset"),
    "event_type": string(enum=["input", "step", "control"]),
    "policy": string(enum=["modeled", "conservative"]),
    "role": string("来源的使用类别", enum=["any", "data", "address", "control", "length"]),
    "address": string("访存起始地址（十六进制）；配合 address_length"),
    "address_length": integer("访存范围，默认 1", 1, 1048576),
}


def contracts(contract):
    network = obj({
        "transport": string(enum=["tcp", "udp"]), "host": string("IP 地址，默认 127.0.0.1；不做无界 DNS 查询"),
        "port": integer("目标监听端口", 1, 65535),
        "startup_delay_ms": integer("UDP 无连接就绪检测；显式等待毫秒，默认 0", 0, 30000),
        "exchanges": {"type": "array", "minItems": 1, "maxItems": 64, "items": obj({
            "send_hex": string("完整发送字节；与 send_chunks 二选一，允许空串", minLength=0),
            "send_chunks": {"type": "array", "minItems": 1, "maxItems": 64, "description": "仅 TCP；顺序发送，不能保证 TCP 包或目标 recv 边界", "items": obj({
                "send_hex": string("此段字节", minLength=0),
                "delay_before_ms": integer("发送此段之前等待，受总 timeout 限制", 0, 30000)}, ["send_hex"])},
            "receive_bytes": integer("TCP 精确读取该长度；UDP 接收一个不超过该长度的报文，默认 0", 0, 65536),
            "receive_mode": string("TCP 默认 exact；until_close 要求服务端关闭连接（keep-alive 会等到总超时）；idle 在至少收到一字节后等待空闲结束，不证明消息边界", enum=["exact", "until_close", "idle"]),
            "max_receive_bytes": integer("非 exact 模式的响应上限，默认 65536；超过报错", 1, 65536),
            "idle_timeout_ms": integer("idle 模式空闲时长，默认 200 ms；首次响应仍受总 timeout 限制", 1, 30000),
            "reconnect": {"type": "boolean", "description": "TCP：此 exchange 前关闭旧连接并新建连接，默认 false"},
        })},
    }, ["transport", "port", "exchanges"])
    query = {**TRACE, "kind": string(enum=["inputs", "outputs", "events", "instructions", "tags", "diagnostics", "flow"]),
             "tag_id": integer("kind=tags 时逐页展开此标签的全部来源；cursor 为来源偏移", 0),
             "diagnostic_type": string("默认 dynamic；静态不支持提示不证明已执行", enum=["dynamic", "gap", "conservative", "unsupported_static"]),
             **SOURCE, **FILTERS, "event_type": string(enum=["input", "step", "control", "model", "output"]), **PAGE}
    return [
        contract("track_run", "在 Pin 下真实运行 Linux x86-64 目标并采集污点。先 check_engines；长任务通过 job_submit。默认 30 秒/100000 事件；返回质量摘要、trace_id 和下一步建议。stdin 与网络重放可直接驱动目标；超时/截断保留证据但报告失败。",
            obj({"target_path": string(), "args": {"type": "array", "maxItems": 256, "items": string()},
                 "env": {"type": "object"}, "cwd": string(),
                 "stdin_hex": string("与 stdin_path 二选一；默认关闭 stdin", minLength=0), "stdin_path": string(),
                 "network": network, "fd": integer("-1 自动选择 socket；stdin 通常设 0", -1),
                 "stop_after_exchanges": {"type": "boolean", "description": "默认 false；重放完成后 SIGTERM 目标；仅退出 0 且日志结构完整时成功，信号 gap 保留"},
                 "replay_settle_ms": integer("主动停止前等待目标处理的时间，默认 100 ms；不证明异步工作完成", 0, 30000),
                 "address_loads": {"type": "boolean", "description": "默认 false；将访存地址来源保守加入加载值，适合 ctype 等查表；会扩大污点，标记 conservative"},
                 "address_load_policy": string("需要 address_loads=true；默认 all 混合基址与索引历史；index_only 仅注入机器寻址索引，适合部分 ctype 查表，不能保证任意编译形式都覆盖", enum=["all", "index_only"]),
                 "comparison_models": {"type": "boolean", "description": "默认 true；对可识别的导入 strcmp/strncmp/memcmp/bcmp 返回值做保守前缀来源汇总，包含相等路径；不覆盖一般隐式流/内联比较，严格模式拒绝受污点的模型"},
                 "all_reads": {"type": "boolean", "description": "默认 false；true 有意标记文件/管道等读取，网络分析通常保持 false"}, "values": {"type": "boolean"},
                 "flow": {"type": "boolean"}, "strict": {"type": "boolean"},
                 "max_input": integer("每次读取标记、比较模型扫描及输出快照上限，默认 1048576", 1, 16777216),
                 "max_events": integer("默认 100000；0 禁用事件上限，仍受时间/文件预算限制", 0, 100000000),
                 "timeout": integer("总运行秒数，默认 30", 1, 3600),
                 "max_output_mb": integer("采集文件总量软上限，默认 256 MiB；轮询有少量超调", 1, 4096)}, ["target_path"])),
        contract("track_import", "快照导入 schema 1 JSONL 并建立持久索引，无需 Pin。默认拒绝不完整日志；allow_partial=true 可分析有效前缀，质量警告始终保留。",
            obj({"path": string(), "allow_partial": {"type": "boolean"}}, ["path"])),
        contract("track_summary", "优先使用：查看采集质量、重点位置、输入概览和建议下一步；省略 trace_id 列出最近采集（含运行中/被取消的采集）。完整结束不等于语义无缺口。",
            obj({**TRACE, **PAGE})),
        contract("track_query", "分页查证据：inputs 原始输入片段；outputs 网络输出字节及 source_runs 来源（系统调用入口快照，成功返回长度裁剪）；events 事件；instructions 静态定义；tags 来源；diagnostics 缺口；flow 已观察控制流边。可按输入字节来源和线程/函数等筛选。非 events/flow 只接受各自适用过滤器。",
            obj(query, ["trace_id", "kind"])),
        contract("track_explain", "解释一个动态事件：逐操作数来源、执行前值、预计写入标签、地址依赖、证据位置和代码坐标。可关联同线程最近的已记录标志位写入候选；不伪造精确切片或执行后数值。",
            obj({**TRACE, "seq": integer("动态事件序号", 1),
                 "operand": integer("只解释指定操作数，从 0 开始"),
                 "origin_limit": integer("每个来源列表最多返回条数，默认 32", 1, 256)}, ["trace_id", "seq"])),
        contract("track_influence", "回答输入这些字节影响哪里：按代码位置聚合数据传播、地址依赖、分支条件/目标、接收长度，给出事件证据与排名。先用于定位，再 track_explain 深入。",
            obj({**TRACE, **SOURCE, **FILTERS, **PAGE}, ["trace_id", "input_id"])),
        contract("track_compare", "比较两次采集中显式对应的输入字节范围：代码位置影响、来源类别、观察到的分支结果与次数。按模块身份/相对地址对齐，局部 ID 和绝对地址不跨运行比较；差异不是因果证明。",
            obj({"left_trace_id": string(), "right_trace_id": string(),
                 "left_input_id": integer(minimum=1), "right_input_id": integer(minimum=1),
                 "left_offset": integer(), "right_offset": integer(),
                 "role": FILTERS["role"], "image": FILTERS["image"], "routine": FILTERS["routine"],
                 "branch_only": {"type": "boolean", "description": "只比较 control 事件，含条件/间接转移、call/return；默认 false"},
                 "direction_only": {"type": "boolean", "description": "仅双方均观察到且 taken/not_taken 方向集合变化的位置；隐含 branch_only，支持 role=any/control；不能代替动态实例对齐"},
                 "length": integer("显式指定两侧等长范围；省略时各比较 offset 至该次读取末尾（两侧可不同长度）", 1, 1048576), **PAGE},
                ["left_trace_id", "right_trace_id", "left_input_id", "right_input_id"])),
        contract("track_export", "导出完整原始轨迹或有界查询报告到独立产物目录，返回路径/长度/SHA-256。报告不是可重新导入的完整采集日志；服务端路径不表示客户端已下载。",
            obj({**TRACE, "format": string(enum=["raw", "json", "jsonl"]),
                 "query": obj({k: v for k, v in query.items() if k != "trace_id"}, ["kind"])}, ["trace_id"])),
    ] + advanced_contracts(contract)


def advanced_contracts(contract):
    window = {"scan_limit": integer("本次最多检查的事件数，默认 2000；另有 16 MiB 工作集预算", 1, 10000)}
    filters = {k: v for k, v in FILTERS.items() if k in ("tid", "seq_start", "seq_end", "image", "routine")}
    scope = {**TRACE, **SOURCE, **filters, **PAGE, **window}
    return [
        contract("track_slice", "从事件操作数字节向后追溯最近已记录写入及来源交集候选链。识别 GPR/SIMD 别名、局部覆盖、输入缓冲与跨线程内存；遇 gap/不匹配/预算停止。结果是可核查候选，不是精确动态切片。",
            obj({**TRACE, "seq": integer(minimum=1), "operand": integer("操作数索引，从 0 开始"),
                 "phase": string(enum=["before", "after"]), "byte_offset": integer(),
                 "byte_length": integer("默认 1，最多 16 字节", 1, 16), **window,
                 "max_nodes": integer("默认 64；含各字节的 before/after 节点", 1, 128),
                 "max_depth": integer("默认 12", 1, 32)}, ["trace_id", "seq", "operand"])),
        contract("track_branches", "专门分析已记录分支：条件来源、间接目标来源、运行值、taken/target，同线程最近标志位写入候选与比较操作数。不求解约束；缺口阻断候选关联。",
            obj({**scope, "instruction_id": integer("可选，只分析指定转移指令", 1),
                 "branch_kind": string("indirect 包含间接跳转、间接 call 和 return", enum=["any", "conditional", "indirect", "call", "return"]),
                 "tainted_only": {"type": "boolean", "description": "默认 true"},
                 "lookback": integer("标志位候选最多回看事件数，默认 100", 1, 500)}, ["trace_id"])),
        contract("track_path", "按指定线程输出有序控制转移窗口、序列指纹及重复后向跳转候选。支持输入来源/函数范围过滤；不是完整指令路径、CFG 或精确循环次数。",
            obj(scope, ["trace_id", "tid"])),
        contract("track_memory", "查看指定内存范围的已记录指令读写和覆盖：访问方向、实际地址、字节来源前后变化、地址依赖与跨线程事件。recv 的内核写入请查 track_query(kind=inputs)，不属于指令写事件。不能恢复未记录时刻的完整内存。",
            obj({**scope, "address": string(), "address_length": integer("范围字节数，默认 1", 1, 1048576),
                 "access": string(enum=["any", "read", "write"]), "changes_only": {"type": "boolean"}}, ["trace_id", "address"])),
        contract("track_values", "按指令列出动态实例的执行前值、来源和预计写入标签；支持操作数/线程筛选，显式区分缺值与短读。用于重复调用、状态变化和循环中的值演变。",
            obj({**scope, "instruction_id": integer(minimum=1), "operand": integer()}, ["trace_id", "instruction_id"])),
        contract("track_compare_paths", "对齐两份轨迹显式指定线程的有界事件序列，定位首次观察分歧、插入/删除和对齐指令的执行前值变化。以镜像/偏移/反汇编匹配，绝不跨运行比较局部标签 ID；差异不是因果证明。",
            obj({"left_trace_id": string(), "right_trace_id": string(), "left_tid": integer(), "right_tid": integer(),
                 "left_seq_start": integer(minimum=1), "right_seq_start": integer(minimum=1),
                 "left_seq_end": integer(minimum=1), "right_seq_end": integer(minimum=1),
                 "image": string(), "routine": string(), "mode": string(enum=["control", "events"]),
                 "max_events": integer("每侧默认 500，最多 2000；超出明确截断", 1, 2000), **PAGE},
                ["left_trace_id", "right_trace_id", "left_tid", "right_tid"])),
        contract("track_map_address", "以轨迹指令为模块锚点换算采集时运行地址与 ELF/Ghidra 静态地址。支持显式模块文件，验证装载段范围；use_ghidra=true 读取实际工程基址。共享库/导入日志的原始模块身份可能无法验证。",
            obj({**TRACE, "instruction_id": integer(minimum=1), "address": string(),
                 "direction": string(enum=["runtime_to_static", "static_to_runtime"]),
                 "module_path": string("默认使用轨迹镜像路径；离线迁移时显式指定"),
                 "static_image_base": string("显式静态基址，与 use_ghidra=true 互斥"),
                 "use_ghidra": {"type": "boolean", "description": "默认 false；true 可能触发首次 Ghidra 分析，建议 job_submit"}},
                ["trace_id", "instruction_id"])),
    ]
