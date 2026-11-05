"""引擎 Provider 的公共异常。

每个引擎目录下的 main.py 实现统一操作接口（操作名 = 工具名），
操作失败时抛出 ProviderError，由调度层转换为 ToolResult。
"""


from contracts.results import ERROR


class ProviderError(Exception):
    """工具执行失败，保留可供入口报告的结果状态。"""

    def __init__(self, message: str, status: str = ERROR, *,
                 limitations: list[str] | None = None,
                 diagnostics: list[dict] | None = None, data=None):
        super().__init__(message)
        self.status = status
        self.limitations = list(limitations or [f"工具操作未完成：{message}"])
        self.diagnostics = list(diagnostics or [
            {"code": "provider_error", "severity": "error", "message": message,
             "details": {}, "suggestions": []},
        ])
        self.data = data
