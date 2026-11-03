---
name: apre
description: 用 APRE 的 binutils 逆向工具分析 ELF 文件——提取/搜索静态字符串、查看符号表、追溯字符串引用。例如从自编译样本 tests/samples/demo 中定位 flag 字符串及其引用函数。
---

# APRE 逆向分析

当需要分析 ELF 二进制、查找其中的静态字符串（如 flag）、查看符号、或追溯某字符串被谁引用时，使用本 skill 的 MCP 工具。

APRE 通过 MCP stdio 暴露工具，`serverName` 为 `apre`，DSH 里实际工具名为 `mcp__apre__<tool>`。

## 可用工具

| 工具 | 作用 | 关键参数 |
| --- | --- | --- |
| `inspect_target` | 查看 ELF 概览：格式/架构/类型/入口点/节表 | `target_path` |
| `search_strings` | 提取并筛选静态可打印字符串 | `target_path`、`pattern`(正则,忽略大小写)、`min_length`(可选) |
| `list_symbols` | 列出已定义符号（函数与全局对象，按地址排序） | `target_path` |
| `get_xrefs` | 追溯某个字符串内容被谁引用（返回反汇编引用行） | `target_path`、`needle` |


## 注意

- `target_path` 用样本路径，例如 `tests/samples/demo`。
- 工具结果里 `file_offset`/`vma` 是地址证据；「未命中」只表示当前工具范围（静态字符串/已定义符号）内没有，不表示目标确实不存在该内容。
- 静态引用不等于运行时一定执行该路径，报告结论时区分「观察到的字符串」与「推导出的引用」与「未知」。