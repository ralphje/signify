__version__ = "0.2.0"


def _print_type(t):
    if t is None:
        return ""
    elif isinstance(t, tuple):
        return ".".join(map(str, t))
    elif callable(t) and hasattr(t(), 'name'):
        return t().name  # used by hashlib
    elif hasattr(t, "__name__"):
        return t.__name__
    else:
        return type(t).__name__
