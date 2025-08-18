from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any, BinaryIO, Literal

from typing_extensions import Self

from signify.authenticode.trust_list import CertificateTrustList
from signify.x509 import Certificate

from .base import AuthenticodeFile


class CtlFile(AuthenticodeFile):
    """Validates CTL (Certificate Trust List) files, which commonly are either
    the Root Certificate Trust Lists (authroot.stl), or Catalog Files (.cat).

    Note that this subclass is not fully type-safe, as it will not return
    :class:`AuthenticodeSignedData` objects.
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

    def verify(  # type: ignore[override]
        self,
        *,
        multi_verify_mode: Literal["any", "first", "all", "best"] = "any",
        expected_hashes: dict[str, bytes] | None = None,
        ignore_parse_errors: bool = True,
        **kwargs: Any,
    ) -> list[tuple[CertificateTrustList, Iterable[list[Certificate]]]]:
        """Verifies the SignedData structure.

        :param expected_hashes: Ignored.
        :param multi_verify_mode: Ignored.
        :param ignore_parse_errors: Ignored.
        :return: the used structure(s) in validation, as a list of tuples, in the form
            (signed data object, certificate chain)
        """
        return [(self.ctl, self.ctl.verify(**kwargs))]

    def iter_signed_datas(  # type: ignore[override]
        self, *, include_nested: bool = True, ignore_parse_errors: bool = True
    ) -> Iterator[CertificateTrustList]:
        """Returns an iterator over the :class:`CertificateTrustList` object.

        :param include_nested: Ignored.
        :param ignore_parse_errors: Ignored.
        :return: iterator of signify.authenticode.SignedData
        """
        yield self.ctl
