from __future__ import annotations

import enum
from typing import TYPE_CHECKING, Any, Callable

from typing_extensions import ParamSpec

from signify.exceptions import (
    AuthenticodeCounterSignerError,
    AuthenticodeInconsistentDigestAlgorithmError,
    AuthenticodeInvalidAdditionalHashError,
    AuthenticodeInvalidDigestError,
    AuthenticodeNotSignedError,
    CertificateVerificationError,
    ParseError,
    VerificationError,
)

_P = ParamSpec("_P")


class AuthenticodeVerificationResult(enum.Enum):
    """This represents the result of an Authenticode verification. If everything is OK,
    it will equal to ``AuthenticodeVerificationResult.OK``, otherwise one of the
    other enum items will be returned. Remember that onl the first exception is
    processed - there may be more wrong.
    """

    OK = enum.auto()
    """The signature is valid."""
    NOT_SIGNED = enum.auto()
    """The provided PE file is not signed."""
    PARSE_ERROR = enum.auto()
    """The Authenticode signature could not be parsed."""
    VERIFY_ERROR = enum.auto()
    """The Authenticode signature could not be verified. This is a more generic error
    than other possible statuses and is used as a catch-all.
    """
    UNKNOWN_ERROR = enum.auto()
    """An unknown error occurred during parsing or verifying."""
    CERTIFICATE_ERROR = enum.auto()
    """An error occurred during the processing of a certificate (e.g. during chain
    building), or when verifying the certificate's signature.
    """
    INCONSISTENT_DIGEST_ALGORITHM = enum.auto()
    """A highly specific error raised when different digest algorithms are used in
    SignedData, SpcInfo or SignerInfo.
    """
    INVALID_DIGEST = enum.auto()
    """The verified digest does not match the calculated digest of the file. This is a
    tell-tale sign that the file may have been tampered with.
    """
    COUNTERSIGNER_ERROR = enum.auto()
    """Something went wrong when verifying the countersignature."""
    INVALID_ADDITIONAL_HASH = enum.auto()
    """The additional file hash, such as the page hash for PE files, or the
    extended digest for MSI files, does not match the calculated hash.
    """

    @classmethod
    def call(
        cls, function: Callable[_P, Any], *args: _P.args, **kwargs: _P.kwargs
    ) -> tuple[AuthenticodeVerificationResult, Exception | None]:
        try:
            function(*args, **kwargs)
        except AuthenticodeNotSignedError as exc:
            return cls.NOT_SIGNED, exc
        except AuthenticodeInconsistentDigestAlgorithmError as exc:
            return cls.INCONSISTENT_DIGEST_ALGORITHM, exc
        except AuthenticodeInvalidDigestError as exc:
            return cls.INVALID_DIGEST, exc
        except AuthenticodeInvalidAdditionalHashError as exc:
            return cls.INVALID_ADDITIONAL_HASH, exc
        except AuthenticodeCounterSignerError as exc:
            return cls.COUNTERSIGNER_ERROR, exc
        except CertificateVerificationError as exc:
            return cls.CERTIFICATE_ERROR, exc
        except ParseError as exc:
            return cls.PARSE_ERROR, exc
        except VerificationError as exc:
            return cls.VERIFY_ERROR, exc
        except Exception as exc:
            return cls.UNKNOWN_ERROR, exc
        else:
            return cls.OK, None


if TYPE_CHECKING:
    from signify.pkcs7 import SignedData

    _MixinBase = SignedData
else:
    _MixinBase = object


class AuthenticodeExplainVerifyMixin(_MixinBase):
    def explain_verify(
        self, *args: Any, **kwargs: Any
    ) -> tuple[AuthenticodeVerificationResult, Exception | None]:
        """This will return a value indicating the signature status of this object.
        This will not raise an error when the verification fails, but rather indicate
        this through the resulting enum

        :return: The verification result, and the exception containing more details
            (if available or None)
        """

        return AuthenticodeVerificationResult.call(self.verify, *args, **kwargs)
