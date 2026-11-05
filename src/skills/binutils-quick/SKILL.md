---
name: binutils-quick
description: 使用 APRE/binutils 确认 ELF、符号和字符串线索
---

先调用 `check_engines`，再对实际目标路径调用 `inspect_target`，确认架构、
入口、ELF 类型及节表。随后用 `list_symbols` 查函数/数据符号，用
`search_strings` 按正则筛选静态字符串；`get_xrefs` 提供启发式引用线索。
读取 `status`、`limitations` 和 `diagnostics`，失败或空列表不等于没有逻辑。

stripped 程序缺少符号是正常情况，交给 Ghidra 识别函数，必要时用 GDB
验证运行时路径。字符串不一定有调用点，静态偏移不能直接当作运行时地址。
所有调用返回 `record_id`，需要复盘时可关联工作目录的记录；不要猜测地址，
用前一步的真实结果构造下一步参数。


get_xrefs 的 kind 区分直接代码引用、自然对齐绝对数据指针候选和经指针的一跳代码引用。
数据候选并不证明运行时使用；检查 coverage、limitations 和 truncated。count=0 不等于无引用。
