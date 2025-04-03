from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable, Iterator
from functools import cached_property
from operator import attrgetter
from typing import BinaryIO

from olefile.olefile import (
    STGTY_ROOT,
    STGTY_STORAGE,
    STGTY_STREAM,
    NotOleFileError,
    OleDirectoryEntry,
    OleFileIO,
)

from signify._typing import HashFunction, HashObject
from signify.authenticode import structures
from signify.authenticode.signed_file import SignedFile
from signify.exceptions import (
    AuthenticodeInvalidExtendedDigestError,
    AuthenticodeNotSignedError,
)

EXTENDED_DIGITAL_SIGNATURE_ENTRY_NAME = "\x05MsiDigitalSignatureEx"
DIGITAL_SIGNATURE_ENTRY_NAME = "\x05DigitalSignature"


class SignedMsiFile(SignedFile):
    def __init__(self, file_obj: BinaryIO):
        """Msi file

        :param file_obj: An MSI file opened in binary file
        """

        self.file = file_obj

    @cached_property
    def _ole_file(self) -> OleFileIO:
        try:
            return OleFileIO(self.file)
        except NotOleFileError:
            raise AuthenticodeNotSignedError("Not a valid OleFile")

    @classmethod
    def _hash_storage_entry(
        cls,
        dir_entry: OleDirectoryEntry,
        hasher: HashObject,
        *,
        dir_entry_path: list[str] | None = None,
    ) -> None:
        """Recursively hashes all streams in a storage entry."""
        dir_entry_path = dir_entry_path or []  # we omit the root directory

        entries = dir_entry.kids
        entries.sort(key=attrgetter("name_utf16"))
        for entry in entries:
            if entry.name in (
                DIGITAL_SIGNATURE_ENTRY_NAME,
                EXTENDED_DIGITAL_SIGNATURE_ENTRY_NAME,
            ):
                continue
            if entry.kids:
                cls._hash_storage_entry(
                    entry, hasher, dir_entry_path=[*dir_entry_path, entry.name]
                )
            else:
                # use the full path to the stream
                with entry.olefile.openstream([*dir_entry_path, entry.name]) as fh:
                    hasher.update(fh.read())

        dir_uid = uuid.UUID(dir_entry.clsid)
        hasher.update(dir_uid.bytes_le)

    def get_fingerprint(
        self,
        digest_algorithm: HashFunction,
    ) -> bytes:
        """Compute the fingerprint for this msi file."""
        hasher = digest_algorithm()

        if self._ole_file.exists(EXTENDED_DIGITAL_SIGNATURE_ENTRY_NAME):
            # MSI is signed with an extended signature
            with self._ole_file.openstream(EXTENDED_DIGITAL_SIGNATURE_ENTRY_NAME) as fh:
                expected_extended_signature = fh.read()
            prehash = self._calculate_prehash(digest_algorithm)
            hasher.update(prehash)
            if prehash != expected_extended_signature:
                raise AuthenticodeInvalidExtendedDigestError(
                    "The expected prehash does not match the digest"
                )

        self._hash_storage_entry(self._ole_file.root, hasher)
        return hasher.digest()

    def iter_signed_datas(
        self, *, include_nested: bool = True, ignore_parse_errors: bool = True
    ) -> Iterator[structures.AuthenticodeSignedData]:
        """Returns an iterator over :class:`AuthenticodeSignedData` objects relevant
        for this MSI file.

        :param include_nested: Boolean, if True, will also iterate over all nested
            SignedData structures
        :param ignore_parse_errors: Present for compatibility reasons. Has no effect
        :raises AuthenticodeNotSignedError: For missing DigitalSignature in the Msi file
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

        if not self._ole_file.exists("\x05DigitalSignature"):
            raise AuthenticodeNotSignedError("missing DigitalSignature")
        # get properties from the stream:
        with self._ole_file.openstream("\x05DigitalSignature") as fh:
            b_data = fh.read()

        yield from recursive_nested(
            structures.AuthenticodeSignedData.from_envelope(b_data)
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

    def _calculate_prehash(self, digest_algorithm: HashFunction) -> bytes:
        hasher = digest_algorithm()
        self._prehash_storage_entry(self._ole_file.root, hasher)
        return hasher.digest()

    @classmethod
    def _prehash_storage_entry(
        cls, dir_entry: OleDirectoryEntry, hasher: HashObject
    ) -> None:
        """Recursively pre-hashes all entries in storage."""
        cls._prehash_entry(dir_entry, hasher)

        entries = dir_entry.kids
        entries.sort(key=attrgetter("name_utf16"))
        for entry in entries:
            if entry.name in ("\x05DigitalSignature", "\x05MsiDigitalSignatureEx"):
                continue
            if entry.kids:
                cls._prehash_storage_entry(entry, hasher)
            else:
                cls._prehash_entry(entry, hasher)

    @staticmethod
    def _prehash_entry(entry: OleDirectoryEntry, hasher: HashObject) -> None:
        """Pre-hash an entry metadata."""
        if entry.entry_type != STGTY_ROOT:
            hasher.update(entry.name_utf16)
        if entry.entry_type in (STGTY_ROOT, STGTY_STORAGE):
            dir_uid = uuid.UUID(entry.clsid)
            hasher.update(dir_uid.bytes_le)

        if entry.entry_type == STGTY_STREAM:
            hasher.update(entry.size.to_bytes(4, "little"))

        hasher.update(
            entry.dwUserFlags.to_bytes(4, "little")
        )  # TODO empty in our case, to check with a msi with flags set

        if entry.entry_type != STGTY_ROOT:
            hasher.update(entry.createTime.to_bytes(8, "little"))
            hasher.update(entry.modifyTime.to_bytes(8, "little"))

        return
