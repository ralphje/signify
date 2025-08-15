from __future__ import annotations

import uuid
from collections.abc import Iterator
from functools import cached_property
from operator import attrgetter
from typing import BinaryIO, cast

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
from signify.authenticode.signed_file import AuthenticodeFile
from signify.exceptions import (
    AuthenticodeInvalidExtendedDigestError,
    AuthenticodeNotSignedError,
    SignedMsiParseError,
    SignifyError,
)

EXTENDED_DIGITAL_SIGNATURE_ENTRY_NAME = "\x05MsiDigitalSignatureEx"
DIGITAL_SIGNATURE_ENTRY_NAME = "\x05DigitalSignature"


class SignedMsiFile(AuthenticodeFile):
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
            raise SignedMsiParseError("Not a valid OleFile")

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

    def get_fingerprint(self, digest_algorithm: HashFunction) -> bytes:
        """Compute the fingerprint for this MSI file."""
        hasher = digest_algorithm()

        if self.has_prehash:
            prehash = self._calculate_prehash(digest_algorithm)
            hasher.update(prehash)

        self._hash_storage_entry(self._ole_file.root, hasher)
        return hasher.digest()

    def iter_signed_datas(
        self, *, include_nested: bool = True, ignore_parse_errors: bool = True
    ) -> Iterator[structures.AuthenticodeSignedData]:
        try:
            if not self._ole_file.exists(DIGITAL_SIGNATURE_ENTRY_NAME):
                raise AuthenticodeNotSignedError(
                    "The MSI file is missing a DigitalSignature stream."
                )
            # get properties from the stream:
            with self._ole_file.openstream(DIGITAL_SIGNATURE_ENTRY_NAME) as fh:
                b_data = fh.read()

            signed_data = structures.AuthenticodeSignedData.from_envelope(
                b_data, signed_file=self
            )
            if include_nested:
                yield from signed_data.iter_recursive_nested()
            else:
                yield signed_data
        except SignedMsiParseError:
            if not ignore_parse_errors:
                raise
        except SignifyError:
            raise
        except Exception as e:
            # Rewrap any parse errors encountered
            if not ignore_parse_errors:
                raise SignedMsiParseError(str(e))

    def verify_additional_hashes(
        self, signed_data: structures.AuthenticodeSignedData
    ) -> None:
        """Verifies the extended digest of MSI files."""
        if not self.has_prehash:
            return

        with self._ole_file.openstream(EXTENDED_DIGITAL_SIGNATURE_ENTRY_NAME) as fh:
            expected_extended_signature = fh.read()

        prehash = self._calculate_prehash(signed_data.digest_algorithm)
        if prehash != expected_extended_signature:
            raise AuthenticodeInvalidExtendedDigestError(
                "The expected prehash does not match the digest"
            )

    @property
    def has_prehash(self) -> bool:
        """Pre-hashes are 'metadata' hashes used when the MsiDigitalSignatureEx
        section is present. The pre-hash only hashes metadata, and the basic hash
        hashes the file content only.

        The pre-hash is prepended to the MSI's basic hash.
        """
        return cast(bool, self._ole_file.exists(EXTENDED_DIGITAL_SIGNATURE_ENTRY_NAME))

    def _calculate_prehash(self, digest_algorithm: HashFunction) -> bytes:
        """Calculates the MSI file's pre-hash. See :attr:`has_prehash`."""
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

    @classmethod
    def _prehash_entry(cls, entry: OleDirectoryEntry, hasher: HashObject) -> None:
        """Pre-hash an entry metadata."""
        if entry.entry_type != STGTY_ROOT:
            hasher.update(entry.name_utf16)
        if entry.entry_type in (STGTY_ROOT, STGTY_STORAGE):
            dir_uid = uuid.UUID(entry.clsid)
            hasher.update(dir_uid.bytes_le)

        if entry.entry_type == STGTY_STREAM:
            hasher.update(entry.size.to_bytes(4, "little"))

        # TODO: empty in our case, to check with a msi with flags set
        hasher.update(entry.dwUserFlags.to_bytes(4, "little"))

        if entry.entry_type != STGTY_ROOT:
            hasher.update(entry.createTime.to_bytes(8, "little"))
            hasher.update(entry.modifyTime.to_bytes(8, "little"))
