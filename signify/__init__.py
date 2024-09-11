from typing import Any, cast

__version__ = "0.7.1"


def _print_type(t: Any) -> str:
    if t is None:
        return ""
    elif isinstance(t, tuple):
        return ".".join(map(str, t))
    elif callable(t) and hasattr(t(), "name"):
        return cast(str, t().name)  # used by hashlib
    elif hasattr(t, "__name__"):
        return cast(str, t.__name__)
    else:
        return type(t).__name__
