"""多引擎组合 Provider：按工具名前缀路由到各引擎。

引擎通过 engine_info.py 的注册表自动发现——添加新引擎时只需在
tools/<engine>/config.py 中调用 register_engine()，入口代码无需修改。

路由规则：
  - prefix=None 的引擎匹配所有工具名（默认引擎，如 binutils 的无前缀工具）
  - prefix="ghidra_" 的引擎只匹配以 ghidra_ 开头的工具
  - 注册顺序决定优先级：先注册的先匹配
"""

from __future__ import annotations

import os
import uuid

_SERVER_PID = os.getpid()
_SERVER_INSTANCE_ID = "apre-" + uuid.uuid4().hex


class CompositeProvider:
    def __init__(self):
        self._routes: list[tuple[str | None, object]] = []
        self._engines: dict[str, object] = {}
        self._jobs = None
        self._workspace = os.path.abspath(
            os.environ.get("APRE_WORKSPACE") or os.path.join(os.getcwd(), "work"))

    def register(self, prefix: str | None, provider, *, engine_name: str | None = None) -> None:
        """注册引擎。prefix=None 表示默认引擎（匹配所有工具名）。"""
        self._routes.append((prefix, provider))
        if engine_name is not None:
            self._engines[engine_name] = provider

    @classmethod
    def auto_build(cls, cfg) -> "CompositeProvider":
        """自动发现所有引擎并构建 CompositeProvider。

        扫描 tools/ 下的引擎目录，import 各 config.py 触发 register_engine()，
        然后从注册表获取 Provider 工厂信息，动态加载并注册。
        """
        from tools.engine_info import auto_discover, get_all_engines
        import importlib

        auto_discover()
        provider = cls()
        provider._workspace = os.path.abspath(getattr(cfg, "workspace", "."))
        for info in get_all_engines():
            mod = importlib.import_module(info.provider_module)
            pcls = getattr(mod, info.provider_class)
            provider.register(info.prefix, pcls(cfg), engine_name=info.name)
        return provider

    def check_engines(self, args: dict) -> dict:
        """检查所有引擎工具的可用性，返回缺失引擎的下载指引。

        环境未就绪时要求 Agent 停止分析并征求安装许可；
        获准安装后必须重启 APRE MCP 服务并复检，才能恢复分析。
        """
        from tools.engine_info import check_all_engines
        result = check_all_engines(self._engines)
        result["server_instance_id"] = _SERVER_INSTANCE_ID
        result["server_pid"] = _SERVER_PID
        return result

    # --- 后台作业（跨引擎的异步执行层，见 src/jobs.py） ---
    def _job_manager(self):
        if getattr(self, "_jobs", None) is None:
            from jobs import JobManager
            self._jobs = JobManager(self._workspace)
        return self._jobs

    def job_submit(self, args: dict) -> dict:
        return self._job_manager().submit(args["tool_name"], args["arguments"])

    def job_status(self, args: dict) -> dict:
        return self._job_manager().status(args["job_id"], args.get("wait", 0))

    def job_list(self, args: dict) -> dict:
        return self._job_manager().list()

    def job_remove(self, args: dict) -> dict:
        return self._job_manager().remove(args["job_id"])

    def __getattr__(self, name: str):
        # 保护内部属性（_routes 等是实例属性，正常查找即可命中，不会走到这里）
        if name.startswith("_"):
            raise AttributeError(name)
        for prefix, provider in self._routes:
            if prefix is None or name.startswith(prefix):
                fn = getattr(provider, name, None)
                if fn is not None:
                    return fn
        raise AttributeError(name)
