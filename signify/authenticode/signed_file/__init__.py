from .base import AuthenticodeFile
from .pe import SignedPEFile, SignedPEFingerprinter
from .signeddata import AuthenticodeSignedDataFile

__all__ = [
    "AuthenticodeFile",
    "AuthenticodeSignedDataFile",
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
