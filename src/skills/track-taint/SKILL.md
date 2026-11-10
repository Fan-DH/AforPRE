---
name: track-taint
description: 使用 APRE/track 高效定位输入字节影响、解释污点证据并验证实验差异
---

目标是回答具体分析问题，例如“输入第 4–5 字节控制哪个分支”，每次调用优先缩小范围。
先 `check_engines`，真实采集要求 track 条目 available=true；离线导入/查询不依赖 Pin。
需要长时间运行或等待网络输入时，使用 `job_submit(tool_name="track_run", arguments=...)`，
再 `job_status`。done 只表示 worker 完成，还要检查 result.status。

推荐顺序：

1. `track_run` 提供目标、真实输入及必要选项。stdin 用 `fd=0` 加 stdin_hex/stdin_path；
   自动 socket 选择保持 fd=-1；文件解析按需 all_reads=true。所有值采集默认开启。
   输入长度、超时、事件数有预算；不要把读取编号当作应用层报文边界。
2. 阅读返回的 quality 和 next_steps。没有 input 时先排查来源和驱动；缺 summary、gap、
   conservative 或短读时先检查 diagnostics，不能把空结果当作“没有依赖”。
   issues 只列结构错误，语义问题在 semantic_issues；gaps 是总数，execution_gaps 与
   termination_gaps 分开看。expected_stop 表示带重放停止标记的 SIGTERM，仍不证明语义完整。
   出现 unpropagated_address_only_events/possible_address_only 时，下游分支可能漏报。
3. `track_query(kind="inputs")` 确认实际字节、source_kind/selection_reason 与 input_id；
   网络来源也可能使用 read/readv，不要仅凭 syscall 编号判断。summary.input_selection_warnings
   提示来源不匹配时先核对；all_reads 是有意采集文件，不是自动 socket 模式的必要参数。`track_influence` 选择 input_id、
   offset、length。优先按 role=control/address/length 或 routine/image 定位关键位置。
4. 从排名结果的 first_seq/next_call 调用 `track_explain`。查看每个操作数的 before_origins、
   after_origins、address_origins 和 value_before；必要时指定 operand 控制返回大小。
   before_is_data_input=false 的旧目的标签不是新值依赖，after 不是执行后具体值。
   查表加载同时看 base_origins、index_origins、load_address_origins：选址的指针历史不等于
   当前输入字节。before_origins 也可能含先前传播的地址来源，不能从合并标签事后拆出纯数据流。
5. 用 location.image/image_offset 衔接静态分析；有 elf_virtual_address 时仍检查 Ghidra
   工程是否重定位。GDB 新运行的 ASLR 地址重新换算，不能沿用 Pin 的 runtime_address。
6. 需要验证猜想时，仅修改相关输入字节再采集；`track_compare` 明确提供两次 input_id
   和对应 offset。省略 length 时两侧分别比较剩余输入；字段实验显式指定等长 length。观察差异不是因果证明，多线程调度和读取分段也能造成变化。
   大响应/完整路径差异优先 `track_compare_paths(mode="control")`，明确两侧线程和窗口；
   aligned_change 若 change_scope=values_only（例如 rflags 值变但 taken 未变），不能称为分支改变。
   `track_compare(role="control",branch_only=true)` 聚焦控制事件；direction_only=true 只保留
   双方观察到的方向集合变化，不做动态实例对齐，也不包含单侧位置。

复杂二进制优先使用以下专用工具，避免手工拼接大量原始事件：

| 分析问题 | 工具与衔接 |
|---|---|
| 一个操作数如何走到这里？ | track_slice(seq,operand,phase,byte_offset)，从已知事件字节向后追溯；先看 unresolved、budget_cuts 与 exact_slice=false |
| 哪些输入决定比较或跳转？ | track_branches，直接查看条件来源、间接目标数据来源、taken 及候选标志位写入的比较值 |
| 线程走了哪些已记录分支？ | track_path 必须指定 tid；看有序转移和 loop_candidates，重复后向转移不等于已证明的循环次数 |
| 某缓冲区被怎样读写和覆盖？ | track_memory(address,address_length,access)，区分数据来源和地址来源；changes_only 仅筛选标签变化 |
| 一条指令在循环中的值怎样变化？ | track_values(instruction_id,operand)，按 seq 查看执行前值；value_available/value_complete 必须检查 |
| 两次执行从哪里开始不同？ | track_compare_paths 明确提供两侧 tid；mode=control 比分支，mode=events 增加指令序列及带标签操作数值比较 |
| 怎样把轨迹地址交给 Ghidra？ | track_map_address(instruction_id,use_ghidra=true) 读取实际工程基址；首次分析用 job_submit；读取 module_file_identity_verified |

这些工具均复用 trace_id，不会自动重跑目标。默认扫描预算、返回分页和质量字段始终有效。
track_path 的候选与指纹针对 analysis_window；翻页前后的候选不能直接累加为循环迭代数。
track_compare_paths 的 left_window/right_window 截断表示只比较了前缀，即使 total_changes=0
也不能据此认定整个执行一致；重复序列可能有多种对齐。新工具说明见 [复杂分析参考](references/advanced.md)。

不要把整份 trace 塞进上下文。query/influence 使用 limit 和返回的 next_cursor；输入原始
字节使用 byte_window.next_offset；标签完整来源使用 query(kind="tags",tag_id=...,cursor=...)。
每条事件的 line/seq、每次工具的 record_id 都可复查。query(kind="flow") 仅表示已记录边，
query(kind="diagnostics") 默认展示动态缺口/回退；静态不支持提示需 diagnostic_type="unsupported_static"。
通过 track_export 保存原始轨迹或有界报告，JSON/JSONL 报告不是完整的采集日志。

网络驱动可以放进 track_run.network：明确 TCP/UDP、IP、端口和 exchanges，发送内容用 hex；
TCP 的首次成功连接就是实验连接。服务端推荐显式 stop_after_exchanges=true，在重放完成后
等待 replay_settle_ms（默认 100 ms）再 SIGTERM；timeout 默认 30 秒仍是总预算。目标必须正常
关闭且日志结构完整才能成功，不会因启用主动停止而隐藏真正失败。
receive_mode 默认 exact，receive_bytes 是精确长度；until_close 要求服务端关闭连接，HTTP
请求可按协议使用 Connection: close，keep-alive 不关闭会一直等到总超时。idle 是收到数据后
等待空闲（默认 200 ms）的启发式，不证明消息边界。未知长度用 max_receive_bytes 限制响应；
reconnect=true 在该 exchange 前关闭旧连接并顺序重连。UDP 仍需按场景指定 startup_delay_ms。
preview_truncated 只表示 MCP hex 预览缩短，完整内容在 replay.json；response_truncated 才表示
接收上限截断。不要自动重试已经部分发送的实验。

ctype/tolower/表查表场景：先查地址依赖，必要时显式 address_loads=true、
address_load_policy="index_only" 进行采集。该模式只注入机器寻址的索引来源，可减少基址历史
污染，但不覆盖所有编译形式（例如索引先算进基址）。all 是启用 address_loads 后的兼容默认，
保守混合基址与索引，适合提高召回，不适合声称单字节精确归因。address_loads 默认 false；
两种模式都不证明因果关系，也不自动重跑目标。详细选项见 [工作流参考](references/workflow.md)。

取消使用 job_remove；它会停止目标并移除作业目录，轨迹保留在 artifacts/track。
取消后 track_summary 不传 trace_id 可找到最近轨迹，再分析有效前缀。超时/失败会返回 trace_id，
先看现有证据再决定是否重新运行；取消可能缺少最终工具记录，manifest 与原始文件仍保留。

来源标签是集合；track_slice 构造的是有界候选证据图，不是完整依赖图。不宣称精确动态切片、一般隐式流、TLS 明文自动标记、
跨进程传播、字段/语义/状态机推断。更多参数及边界见 [工作流参考](references/workflow.md)。

比较成功路径：默认 comparison_models=true 对可识别的导入 strcmp/strncmp/memcmp/bcmp
返回值建模，包括返回 0；model 事件是保守 ABI 前缀来源并集。query(events,event_type="model")
与 explain(seq) 可查依据，comparison_models=false 可作基线。strict 拒绝受污点模型；内联、
自定义比较和外部状态返回值仍可能漏报。不要把未观察到来源视为字段未被解析。

响应字节溯源：query(kind="outputs") 查看成功发送片段的 source_runs，按 input_id/offset/length
筛选来源，再用 tag_id 展开截断来源。标签 0 不证明无依赖；控制分支生成的常量未必带输入标签。
输出是系统调用入口快照、成功返回长度裁剪，不是应用协议字段或远端接收证明。

分阶段发送：exchange 使用 send_chunks=[{send_hex,delay_before_ms}, ...]，与 send_hex 二选一，
只支持 TCP。延迟受总 timeout 限制；分段不保证目标 recv 边界。不把多个 input_id 自动拼成一个报文。
详细参数与模型边界见 [工作流参考](references/workflow.md)。
