__version__ = "0.1.2"


def _print_type(t):
    if t is None:
        return ""
    elif isinstance(t, tuple):
        return ".".join(t)
    elif hasattr(t, "__name__"):
        return t.__name__
    else:
        return type(t).__name__
