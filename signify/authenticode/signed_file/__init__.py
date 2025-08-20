from .base import AuthenticodeFile
from .ctl import CtlFile
from .flat import FlatFile
from .pe import SignedPEFile, SignedPEFingerprinter
from .signature import AuthenticodeSignatureFile

__all__ = [
    "AuthenticodeFile",
    "AuthenticodeSignatureFile",
    "CtlFile",
    "FlatFile",
    "SignedPEFile",
    "SignedPEFingerprinter",
]

# SignedMsiFile is not necessarily available, as olefile is an optional dependency.
try:
    from .msi import SignedMsiFile
except ImportError:
    pass
else:
    __all__.extend(["SignedMsiFile"])
