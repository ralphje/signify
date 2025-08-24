from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any, BinaryIO, Literal

from typing_extensions import Self

from signify.authenticode.indirect_data import IndirectData
from signify.authenticode.signed_data import AuthenticodeSignature
from signify.authenticode.trust_list import CertificateTrustList
from signify.pkcs7 import SignedData
from signify.x509 import Certificate

from .base import AuthenticodeFile


class CtlFile(AuthenticodeFile):
    """Validates CTL (Certificate Trust List) files, which commonly are either
    the Root Certificate Trust Lists (authroot.stl), or Catalog Files (.cat).

    Note that this subclass is not fully type-safe, as it will not return
    :class:`AuthenticodeSignature` objects.
    """

    def __init__(self, ctl: CertificateTrustList) -> None:
        """
        :param ctl: The CertificateTrustList object we're operating on.
        """
        self.ctl = ctl

    @classmethod
    def _try_open(
        cls, file_obj: BinaryIO, file_name: str | None, header: bytes
    ) -> CtlFile | None:
        if header.startswith(b"\x30"):
            return cls.from_envelope(file_obj.read())
        return None

    @classmethod
    def from_envelope(cls, data: bytes) -> Self:
        """Creates a :class:`CtlFile` from a data envelope."""
        return cls(CertificateTrustList.from_envelope(data))

    def _calculate_expected_hashes(
        self,
        signed_datas: Iterable[SignedData],
        expected_hashes: dict[str, bytes] | None = None,
    ) -> dict[str, bytes]:
        # Do not pre-calculate hashes for this specific file type
        return expected_hashes or {}

    def verify_signature(
        self,
        signed_data: AuthenticodeSignature | CertificateTrustList,
        *,
        expected_hashes: dict[str, bytes],
        **kwargs: Any,
    ) -> tuple[SignedData, IndirectData | None, Iterable[list[Certificate]]]:
        """Change signature verification to directly use the CertificateTrustLis
        instead of its TrustSubjects.
        """
        if isinstance(signed_data, CertificateTrustList):
            return signed_data, None, signed_data.verify(**kwargs)
        return super().verify_signature(
            signed_data, expected_hashes=expected_hashes, **kwargs
        )

    def iter_embedded_signatures(  # type: ignore[override]
        self, *, include_nested: bool = True, ignore_parse_errors: bool = True
    ) -> Iterator[CertificateTrustList]:
        """Returns an iterator over the :class:`CertificateTrustList` object.

        :param include_nested: Ignored.
        :param ignore_parse_errors: Ignored.
        """
        yield self.ctl
