from __future__ import annotations

import os
from collections.abc import Iterator
from typing import BinaryIO

from typing_extensions import Self

from signify.authenticode.signed_data import AuthenticodeSignedData

from .base import AuthenticodeFile


class AuthenticodeSignedDataFile(AuthenticodeFile):
    """Simple transparent :class:`AuthenticodeFile` class that operates on an
    already-parsed :class:`AuthenticodeSignedData`. This can be used in
    places where the parsed SignedData object is present, but the original file is no
    longer present, or for parsing P7X files.

    Note that the :meth:`get_fingerprint` method is not implemented, so all hashes
    must be provided as expected hashes in the :meth:`verify` method.

    Remember that you can directly manipulate :class:`AuthenticodeSignedData`
    objects and that this class is a very simple shim. If you don't need the features
    provided by :class:`AuthenticodeFile`, simply use the
    :class:`AuthenticodeSignedData` directly.
    """

    def __init__(self, signed_data: AuthenticodeSignedData | None) -> None:
        """
        :param signed_data: The signed data object we're operating on. Can be None
            to allow filling it in later (see :meth:`from_envelope`).
        """
        self.signed_data = signed_data

    @classmethod
    def _try_open(
        cls, file_obj: BinaryIO, file_name: str | None, header: bytes
    ) -> AuthenticodeSignedDataFile | None:
        if header.startswith(b"PKCX"):
            file_obj.seek(4, os.SEEK_CUR)
            return cls.from_envelope(file_obj.read())
        return None

    @classmethod
    def from_envelope(cls, data: bytes) -> Self:
        """Creates a :class:`AuthenticodeSignedDataFile` from a data envelope. This
        will instantiate an 'empty' :class:`AuthenticodeSignedDataFile` object, and
        fill it in.
        """
        signed_file = cls(None)
        signed_file.signed_data = AuthenticodeSignedData.from_envelope(
            data, signed_file=signed_file
        )
        return signed_file

    def iter_signed_datas(
        self, *, include_nested: bool = True, ignore_parse_errors: bool = True
    ) -> Iterator[AuthenticodeSignedData]:
        if self.signed_data is None:
            raise Exception("Object not instantiated yet.")
        if include_nested:
            yield from self.signed_data.iter_recursive_nested()
        else:
            yield self.signed_data
