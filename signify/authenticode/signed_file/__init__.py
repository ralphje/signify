from .base import AuthenticodeFile
from .ctl import CtlFile
from .flat import FlatFile
from .pe import SignedPEFile, SignedPEFingerprinter
from .signed_data import AuthenticodeSignedDataFile

__all__ = [
    "AuthenticodeFile",
    "AuthenticodeSignedDataFile",
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
