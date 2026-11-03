"""引擎 Provider 层：每个引擎一个目录，统一操作接口由 base 约定。"""

from .base import ProviderError

__all__ = ["ProviderError"]