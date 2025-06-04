from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from typing import BinaryIO


from signify.authenticode import structures
from signify.authenticode.signed_file import SignedFile


class RawCertificateFile(SignedFile):
    def __init__(self, file_obj: BinaryIO):
        """Load a RawCertificateFile object.
        :param file_obj: A file-like object containing the raw certificate data.
        """
        self.file = file_obj


    def iter_signed_datas(
        self, *, include_nested: bool = True, ignore_parse_errors: bool = True
    ) -> Iterator[structures.AuthenticodeSignedData]:
        """Returns an iterator over :class:`AuthenticodeSignedData` objects relevant
        for this raw certificate.

        :param include_nested: Boolean, if True, will also iterate over all nested
            SignedData structures
        :param ignore_parse_errors: Present for compatibility reasons. Has no effect
        :raises signify.authenticode.AuthenticodeParseError: For parse errors in the
            SignedData
        :return: iterator of signify.authenticode.SignedData
        """

        def recursive_nested(
            signed_data: structures.AuthenticodeSignedData,
        ) -> Iterator[structures.AuthenticodeSignedData]:
            yield signed_data
            if include_nested:
                for nested in signed_data.signer_info.nested_signed_datas:
                    yield from recursive_nested(nested)

        cert_data = self.file.read()

        yield from recursive_nested(
            structures.AuthenticodeSignedData.from_envelope(cert_data)
        )

    def _calculate_expected_hashes(
        self,
        signed_datas: Iterable[structures.AuthenticodeSignedData],
        expected_hashes: dict[str, bytes] | None = None,
    ) -> dict[str, bytes]:
        if expected_hashes is None:
            expected_hashes = {}

        # Calculate which hashes we require for the signedinfos
        digest_algorithms = set()
        for signed_data in signed_datas:
            digest_algorithms.add(signed_data.digest_algorithm)

        # Calculate which hashes are needed
        provided_hashes = {getattr(hashlib, t) for t in expected_hashes}
        needed_hashes = digest_algorithms - provided_hashes

        # Calculate the needed hashes
        for digest_algorithm in needed_hashes:
            fingerprint = self.get_fingerprint(digest_algorithm)
            expected_hashes[digest_algorithm().name] = fingerprint

        return expected_hashes
