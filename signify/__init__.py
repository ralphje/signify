__version__ = "0.1.3"


def _print_type(t):
    if t is None:
        return ""
    elif isinstance(t, tuple):
        return ".".join(map(str, t))
    elif hasattr(t, "__name__"):
        return t.__name__
    elif callable(t) and hasattr(t(), 'name'):
        return t().name  # used by hashlib
    else:
        return type(t).__name__
