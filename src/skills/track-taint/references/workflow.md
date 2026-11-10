# 参数与证据衔接

采集示例（目标路径替换为真实 ELF）：

```json
{"tool_name":"track_run","arguments":{"target_path":"/absolute/parser","fd":0,"stdin_hex":"4102","timeout":30,"max_events":100000}}
```

将以上对象传给 job_submit，再查询 job_status。采集成功也必须读取 quality：
structural_complete 只表示已检查记录结构/引用/序号及最终计数；semantic_completeness_proven
始终为 false。unsupported_static 只说明插桩发现，gap 才表示已检测执行缺口。
保守算术可能 policy=modeled；conservative_events=0 也不证明精确传播。

工具选择：

| 问题 | 调用 |
|---|---|
| 读取了哪些数据？ | track_query(kind=inputs)，保留 returned/stored/tainted 与 flags 的区别 |
| 哪些代码受这一字段影响？ | track_influence(input_id,offset,length)，role 可选 data/address/control/length |
| 这个操作数从哪来？ | track_explain(seq,operand)，多源集合可包含多次读取 |
| 如何展开大标签？ | track_query(kind=tags,tag_id,cursor,limit)；tag 0 来源为空 |
| 分支是否改变？ | track_query(kind=flow) 或 track_compare；taken 是观察到的方向 |
| 哪些地址受输入影响？ | track_influence(role=address)，或 query(events,address,address_length) |
| 后续 read 长度来自哪里？ | track_influence(role=length)，再 explain input 事件的 length_origins |
| 有哪些不可信部分？ | track_query(kind=diagnostics)，再看 quality.issues 与 limitations |

query(events) 支持 tid、seq_start/seq_end（含末端）、instruction_id、image/routine 子串、
event_type、policy、来源范围、role 和访存范围重叠筛选；不会接收任意 SQL 或表达式。
query(inputs) 支持 input_id、tid 和字节切片；query(instructions) 支持指令 ID、镜像、函数；
query(tags) 支持来源范围或单标签展开；不适用的过滤器会报错，不会静默忽略。

cursor 是不透明的继续位置，原样使用 next_cursor；不同 kind/过滤条件之间不要复用。
同一输入的字节窗口最多 4096 字节/64 个片段；缺失字节不补零。
事件查询等单页正文预算约 48 KB，质量/元数据另计。超过单项大小时返回可定位的预览，
完整证据可从原始导出获取；一般查询/解释响应超出约 96 KB 时另有 omitted_fields_bytes 标明省略项。
指令/标签 ID 只在所属 trace 内有效。

Pin 选项在 track_run 中对应 fd、all_reads、values、flow、strict、max_input、max_events。
默认 max_input=1048576、max_events=100000、timeout=30、max_output_mb=256；
max_events=0 关闭事件预算，时间和文件预算仍生效。max_input 上限 16 MiB，timeout 上限
3600 秒；文件预算是轮询软上限，可短暂超调，不是磁盘配额或 Pin 总内存上限。
values=false 不会关闭 input_chunk 原始输入，只关闭指令操作数值；flow=false 仍记录污点控制转移。
run 强制 LD_BIND_NOW=1 并记录设置，以减小懒绑定缺口；这也可能改变目标的动态链接时机。

length_tag 只覆盖标量接收 RDX；readv/recvmsg 的零标签不是无依赖证明。
flag_writer_candidate 仅在同线程此前 200 条已记录指令中寻找，不能当作逐标志位精确证明。
轨迹文件现有格式未记录模块 build-id/加载卸载生命周期；模块身份校验只对本次采集前后
一致的主目标提供有限依据，不能排除 JIT、自修改、同路径模块替换等情况。
track_compare 不对齐后续接收 ID，不比较完整值序列或完整路径；差异定位后用 explain 核实。

Pin/目标运行时 stdout、stderr、重放记录均单独落盘，MCP stdout 始终只传协议。
导入会复制源文件，索引仅分析该快照；正在写入的外部日志应等结束后再导入。
索引拒绝超过 16 MiB 的单条 JSON 记录，并报告有效前缀和具体问题；不会声称已分析剩余内容。

服务端采集：显式 stop_after_exchanges=true 可在重放后 SIGTERM 正常收尾；未知长度且关闭连接
用 network.exchanges[].receive_mode="until_close"；服务端 keep-alive 不关闭时会等到总超时。长连接可用 "idle"（启发式，不证明消息边界）。
reconnect=true 可顺序重连。检查 collection_outcome、退出码与 quality；信号 gap 仍保留。
ctype/tolower 等查表依赖默认只在 address 角色里体现；需要追踪到加载值时显式 address_loads=true，可配合 address_load_policy="index_only" 减少基址历史；
all 会混合基址与索引，index_only 只看机器索引，不能保证所有查表形式都覆盖。两者均接受 conservative 近似。LEA 本身始终传播地址计算源，不依赖此选项。
routine 是未经校验的 Pin 符号提示；优先 image+image_offset。source_byte_count 多于 1 时，不应把
来源并集解释成每字节的精确因果证明。新采集消除重复 instruction id，旧日志 influence 会合并并
列出 instruction_ids；旧 values 查询仍需分别使用这些 ID。

质量与诊断：issues/structural_complete 只论结构，semantic_issues 与 limitations 对应。
gaps 保留原始总数；termination_gaps 只计带 replay_stop_marker 的 expected_stop，execution_gaps
是其余 gap。旧日志的 SIGTERM 不会仅凭信号号被追认为主动停止；停止边界仍无回滚保证。
unpropagated_address_only_events 是无内存数据标签且未注入选址来源的加载事件数，
first_unpropagated_address_seq 可直接 explain；这是漏报风险候选，不是已证明丢失依赖的数量。
influence 的 possible_address_only 表示该位置存在此类无内存数据标签的选址依赖。

运行结果中 preview_truncated 只针对 hex 预览；send_bytes/received_bytes 为记录长度，
send_preview_bytes/received_preview_bytes 为本页展示长度，response_truncated 表示实际接收上限
溢出。完整接收记录在 artifacts.replay（replay.json）；失败时可能只有前缀，仍检查 complete。

compare 可选 role、branch_only、direction_only、image、routine。branch_only 覆盖 control 事件，
包含 call/return；direction_only 排除单侧位置，只看双方观察方向集合变化，可能漏掉集合相同
但顺序不同的动态分歧。大响应优先 compare_paths(mode="control")，看窗口是否截断；
first_observed_control_difference 与 first_observed_difference 分别表示控制变化和任意观察变化，
value_only_changes（如 flags 数值变化）不等于 taken 改变。

## 比较模型、输出与分段重放

track_run.comparison_models 默认 true，对可识别导入 strcmp/strncmp/memcmp/bcmp 使用保守
比较前缀来源模型，含相等结果；false 关闭。原始 model 事件可通过 query(events,event_type="model")
分页查看，explain(seq) 返回 return_sources。strict 拒绝受污点模型。未实现一般隐式流，stat
等外部返回值不能由路径数据标签直接解释。slice 的 comparison_return_model 停止点提供 model_seq。

query(kind="outputs",input_id=...,offset=...,length=...) 筛选带指定输入来源的成功发送片段。
每片最多 64 字节，bytes/tags 和 source_runs 对应；run.offset 相对该次 syscall，不是连接累计
偏移。sources 的 truncated 表示来源预览截断，query(tags,tag_id=run.tag) 可继续。输出快照来自
syscall 入口，按成功发送长度裁剪，覆盖 socket 的 write/writev/sendto/sendmsg；未覆盖零拷贝/
异步 I/O/TLS 解密，也不追踪控制生成常量的隐式来源。max_input 限制输出快照，超出产生 gap。

```json
{"transport":"tcp","port":18081,"exchanges":[{"send_chunks":[
  {"send_hex":"0102"},{"send_hex":"0003414243","delay_before_ms":100}
],"receive_mode":"idle","idle_timeout_ms":200}]}
```

send_chunks 与 send_hex 二选一；每个 exchange 最多 64 段、总发送最多 65507 字节。
延迟 0..30000 ms，仍受 track_run.timeout 限制。replay.json 保存逐段进度与开始时间；
完成发送不保证对方读取次数、TCP 包边界或应用层消息边界。UDP 不接受 send_chunks。

compare 省略 length 时各自选取 offset 到 stored 末尾，range_mode=remaining_input_each_side；
显式 length 时 range_mode=explicit_equal_length。空范围和超过 1048576 字节需显式修正。
influence 条目的 input_id/source_selection 是查询选择；event_input_id 才是读取事件自身编号。
一个指令仍可能含多个输入来源，完整集合以 explain/values 为准。
