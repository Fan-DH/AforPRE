"""引擎 Provider 的公共异常。

每个引擎目录下的 main.py 实现统一操作接口（操作名 = 工具名），
操作失败时抛出 ProviderError，由调度层转换为 ToolResult。
"""


class ProviderError(Exception):
    """工具执行失败（非零退出、超时、缺失工具等）。"""