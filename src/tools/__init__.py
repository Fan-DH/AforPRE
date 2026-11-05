"""引擎 Provider 层：每个引擎一个目录，统一操作接口由 base 约定。

CompositeProvider 提供多引擎按工具名前缀路由的能力。
EngineInfo / Dependency 供各引擎 config 注册环境校验信息。
"""

from .base import ProviderError
from .composite import CompositeProvider
from .engine_info import EngineInfo, Dependency

__all__ = ["ProviderError", "CompositeProvider", "EngineInfo", "Dependency"]
