from .authroot import AUTHROOTSTL_PATH, CertificateTrustList, CertificateTrustSubject
from .signed_file import AuthenticodeFile
from .signed_pe import SignedPEFile, SignedPEFingerprinter
from .structures import (
    CERTIFICATE_LOCATION,
    TRUSTED_CERTIFICATE_STORE,
    TRUSTED_CERTIFICATE_STORE_NO_CTL,
    AuthenticodeCounterSignerInfo,
    AuthenticodeSignedData,
    AuthenticodeSignerInfo,
    AuthenticodeVerificationResult,
    IndirectData,
    PeImageData,
    RFC3161SignedData,
    RFC3161SignerInfo,
    SigInfo,
    TSTInfo,
)

__all__ = [
    "AUTHROOTSTL_PATH",
    "CERTIFICATE_LOCATION",
    "TRUSTED_CERTIFICATE_STORE",
    "TRUSTED_CERTIFICATE_STORE_NO_CTL",
    "AuthenticodeCounterSignerInfo",
    "AuthenticodeFile",
    "AuthenticodeSignedData",
    "AuthenticodeSignerInfo",
    "AuthenticodeVerificationResult",
    "CertificateTrustList",
    "CertificateTrustSubject",
    "IndirectData",
    "PeImageData",
    "RFC3161SignedData",
    "RFC3161SignerInfo",
    "SigInfo",
    "SignedPEFile",
    "SignedPEFingerprinter",
    "TSTInfo",
]

# SignedMsiFile is not necessarily available, as olefile is an optional dependency.
try:
    from .signed_msi import SignedMsiFile
except ImportError:
    pass
else:
    __all__.extend(["SignedMsiFile"])
