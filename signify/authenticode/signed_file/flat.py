from __future__ import annotations

from collections.abc import Iterator
from typing import BinaryIO

from signify._typing import HashFunction
from signify.authenticode.signed_data import AuthenticodeSignature
from signify.fingerprinter import Fingerprinter

from .base import AuthenticodeFile


class FlatFile(AuthenticodeFile):
    """Simple flat file implementation that fully hashes the file's contents."""

    def __init__(self, file_obj: BinaryIO) -> None:
        self.file = file_obj

    def get_fingerprinter(self) -> Fingerprinter:
        """Returns a fingerprinter object for this file."""
        return Fingerprinter(self.file)

    def get_fingerprint(self, digest_algorithm: HashFunction) -> bytes:
        return self.get_fingerprints(digest_algorithm)[digest_algorithm().name]

    def get_fingerprints(self, *digest_algorithms: HashFunction) -> dict[str, bytes]:
        if not digest_algorithms:
            return {}

        fingerprinter = self.get_fingerprinter()
        fingerprinter.add_hashers(*digest_algorithms)
        return fingerprinter.hash()

    def iter_embedded_signatures(
        self, *, include_nested: bool = True, ignore_parse_errors: bool = True
    ) -> Iterator[AuthenticodeSignature]:
        yield from []
