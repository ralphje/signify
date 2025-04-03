<<<<<<< HEAD
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
=======
#!/usr/bin/env python

# This is a derivative, modified, work from the verify-sigs project.
# Please refer to the LICENSE file in the distribution for more
# information. Original filename: fingerprinter.py
#
# Parts of this file are licensed as follows:
#
# Copyright 2010 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""This module effectively implements the relevant parts of the PECOFF_ documentation
to find the relevant parts of the PE structure.

It is also capable of listing all the certificates in the Certificate Table and find
the certificate with type 0x2. The actual parsing of this certificate is perfomed by
:mod:`signify.authenticode`.

.. _PECOFF: http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
"""

from __future__ import annotations

import collections
import hashlib
import logging
import uuid
from _hashlib import HASH
from operator import attrgetter
from typing import Any, BinaryIO, Iterable, Iterator

from olefile.olefile import STGTY_STORAGE, STGTY_STREAM, STGTY_ROOT, OleFileIO, OleDirectoryEntry
from typing_extensions import Literal, TypedDict

from signify._typing import HashFunction
from signify.asn1.hashing import ACCEPTED_DIGEST_ALGORITHMS
from signify.authenticode import structures
from signify.exceptions import AuthenticodeNotSignedError, SignedPEParseError
from signify.x509 import Certificate

logger = logging.getLogger(__name__)

class SignedMsiFile:
    def __init__(self, file_obj: BinaryIO):
        """Msi file

        :param file_obj: A MSI file opened in binary file
        """

        self.file = file_obj
        self._ole_file = OleFileIO(self.file)


    def get_fingerprint(
        self,
        digest_algorithm: HashFunction,
    ) -> bytes:
        """Gets the fingerprint for this msi file."""
        hasher = digest_algorithm()
        hasher.update(self._calculate_prehash(digest_algorithm))
        entries = self._ole_file.root.kids  # TODO handle nested kids
        entries.sort(key=attrgetter('name_utf16'))
        for entry in entries:
            if entry.name in ("\x05DigitalSignature", '\x05MsiDigitalSignatureEx'):
                continue
            with self._ole_file.openstream(entry.name) as fh:
                hasher.update(fh.read())
        
        dir_uid = uuid.UUID(self._ole_file.root.clsid)
        hasher.update(dir_uid.bytes_le)
        return hasher.digest()

    @property
    def signed_datas(self) -> Iterator[structures.AuthenticodeSignedData]:
        """Returns an iterator over :class:`AuthenticodeSignedData` objects relevant for
        this MSI file. See :meth:`iter_signed_datas`
        """

        yield from self.iter_signed_datas()

    def iter_signed_datas(
        self, *, include_nested: bool = True, ignore_parse_errors: bool = True
    ) -> Iterator[structures.AuthenticodeSignedData]:
        """Returns an iterator over :class:`AuthenticodeSignedData` objects relevant
        for this PE file.

        :param include_nested: Boolean, if True, will also iterate over all nested
            SignedData structures
        :param ignore_parse_errors: Indicates how to handle
            :exc:`SignedPEParseError` that may be raised while fetching
            embedded :class:`structures.AuthenticodeSignedData` structures.

            When :const:`True`,  which is the default and seems to be how Windows
            handles this as well, this will fetch as many valid
            :class:`structures.AuthenticodeSignedData` structures until an exception
            occurs.

            Note that this will also silence the :exc:`SignedPEParseError` that occurs
            when there's no valid :class:`AuthenticodeSignedData` to fetch.

            When :const:`False`, this will raise the :exc:`SignedPEParseError` as
            soon as one occurs.
        :raises SignedPEParseError: For parse errors in the PEFile
        :raises signify.authenticode.AuthenticodeParseError: For parse errors in the
            SignedData
        :return: iterator of signify.authenticode.SignedData
        """
        
        # TODO ignore_parse_errors not used

>>>>>>> c524ab5 (Add support for msi #24)
        def recursive_nested(
            signed_data: structures.AuthenticodeSignedData,
        ) -> Iterator[structures.AuthenticodeSignedData]:
            yield signed_data
            if include_nested:
                for nested in signed_data.signer_info.nested_signed_datas:
                    yield from recursive_nested(nested)

<<<<<<< HEAD
        try:
            if not self._ole_file.exists(DIGITAL_SIGNATURE_ENTRY_NAME):
                raise AuthenticodeNotSignedError(
                    "The MSI file is missing a DigitalSignature stream."
                )
            # get properties from the stream:
            with self._ole_file.openstream(DIGITAL_SIGNATURE_ENTRY_NAME) as fh:
                b_data = fh.read()

            yield from recursive_nested(
                structures.AuthenticodeSignedData.from_envelope(
                    b_data, signed_file=self
                )
            )

        except SignedMsiParseError:
            if not ignore_parse_errors:
                raise
        except SignifyError:
            raise
        except Exception as e:
            # Rewrap any parse errors encountered
            if not ignore_parse_errors:
                raise SignedMsiParseError(str(e))

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
=======
        with OleFileIO(self.file) as ole:
            # https://github.com/decalage2/olefile
            if not ole.exists("\x05DigitalSignature"):
                raise ValueError("missing DigitalSignature")
            # get properties from the stream:
            with ole.openstream("\x05DigitalSignature") as fh:
                b_data = fh.read()

        yield from recursive_nested(
            structures.AuthenticodeSignedData.from_envelope(b_data)
        )

    def _calculate_expected_hashes(
        self,
        signed_datas: Iterable[structures.AuthenticodeSignedData],
        expected_hashes: dict[str, bytes] | None = None,
    ) -> dict[str, bytes]:
        """Calculates the expected hashes that are needed for verification. This
        provides a small speed-up by pre-calculating all hashes, so that not each
        individual SignerInfo object is responsible for calculating their own hash.

        :param signed_datas: The signed datas of this object. Provided to allow
            :meth:`verify` to prefetch these
        :param expected_hashes: Hashes provided by the caller of :meth:`verify`
        :return: All required hashes
        """

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

    def verify(
        self,
        *,
        multi_verify_mode: Literal["any", "first", "all", "best"] = "any",
        expected_hashes: dict[str, bytes] | None = None,
        ignore_parse_errors: bool = True,
        **kwargs: Any,
    ) -> list[tuple[structures.AuthenticodeSignedData, Iterable[list[Certificate]]]]:
        """Verifies the SignedData structures. This is a little bit more efficient than
        calling all verify-methods separately.

        :param expected_hashes: When provided, should be a mapping of hash names to
            digests. This could speed up the verification process.
        :param multi_verify_mode: Indicates how to verify when there are multiple
            :class:`structures.AuthenticodeSignedData` objects in this PE file. Can be:

            * 'any' (default) to indicate that any of the signatures must validate
              correctly.
            * 'first' to indicate that the first signature must verify correctly
              (the default of tools such as sigcheck.exe)
            * 'all' to indicate that all signatures must verify
            * 'best' to indicate that the signature using the best hashing algorithm
              must verify (e.g. if both SHA-1 and SHA-256 are present, only SHA-256
              is checked); if multiple signatures exist with the same algorithm,
              any may verify

            This argument has no effect when only one signature is present.
        :param ignore_parse_errors: Indicates how to handle :exc:`SignedPEParseError`
            that may be raised during parsing of the PE file's certificate table.

            When :const:`True`, which is the default and seems to be how Windows
            handles this as well, this will verify based on all available
            :class:`structures.AuthenticodeSignedData` before a parse error occurs.

            :exc:`AuthenticodeNotSignedError` will be raised when no valid
            :class:`structures.AuthenticodeSignedData` exists.

            When :const:`False`, this will raise the :exc:`SignedPEParseError` as soon
            as one occurs. This often occurs before :exc:`AuthenticodeNotSignedError`
            is potentially raised.
        :return: the used structure(s) in validation, as a list of tuples, in the form
            (signed data object, certificate chain)
        :raises AuthenticodeVerificationError: when the verification failed
        :raises SignedPEParseError: for parse errors in the PEFile
        """

        # we need to iterate it twice, so we need to prefetch all signed_datas
        signed_datas = list(
            self.iter_signed_datas(ignore_parse_errors=ignore_parse_errors)
        )

        # if there are no signed_datas, the binary is not signed
        if not signed_datas:
            raise AuthenticodeNotSignedError("No valid SignedData structure was found.")

        # only consider the first signed_data; by selecting it here we prevent
        # calculating more hashes than needed
        if multi_verify_mode == "first":
            signed_datas = [signed_datas[0]]
        elif multi_verify_mode == "best":
            # ACCEPTED_DIGEST_ALGORITHMS contains the algorithms in worst to best order
            best_algorithm = max(
                (sd.digest_algorithm for sd in signed_datas),
                key=lambda alg: [
                    getattr(hashlib, alg) for alg in ACCEPTED_DIGEST_ALGORITHMS
                ].index(alg),
            )
            signed_datas = [
                sd for sd in signed_datas if sd.digest_algorithm == best_algorithm
            ]

        expected_hashes = self._calculate_expected_hashes(signed_datas, expected_hashes)

        # Now iterate over all SignedDatas
        chains = []
        last_error = None
        assert signed_datas
        for signed_data in signed_datas:
            try:
                chains.append(
                    (
                        signed_data,
                        signed_data.verify(
                            expected_hash=expected_hashes[
                                signed_data.digest_algorithm().name
                            ],
                            **kwargs,
                        ),
                    )
                )
            except Exception as e:  # noqa: PERF203
                # best and any are interpreted as any; first doesn't matter either way,
                # but raising where it is raised is a little bit clearer
                if multi_verify_mode in ("all", "first"):
                    raise
                last_error = e
            else:
                if multi_verify_mode not in ("all", "first"):
                    # only return the last one, as we are in mode any/best
                    return chains[-1:]
        if last_error is None:
            return chains
        raise last_error

    def explain_verify(
        self, *args: Any, **kwargs: Any
    ) -> tuple[structures.AuthenticodeVerificationResult, Exception | None]:
        """This will return a value indicating the signature status of this PE file.
        This will not raise an error when the verification fails, but rather
        indicate this through the resulting enum

        :rtype: (signify.authenticode.AuthenticodeVerificationResult, Exception)
        :returns: The verification result, and the exception containing
            more details (if available or None)
        """

        return structures.AuthenticodeVerificationResult.call(
            self.verify, *args, **kwargs
        )
    
    @staticmethod
    def _prehash_entry(entry: OleDirectoryEntry, hasher: HASH):
>>>>>>> c524ab5 (Add support for msi #24)
        if entry.entry_type != STGTY_ROOT:
            hasher.update(entry.name_utf16)
        if entry.entry_type in (STGTY_ROOT, STGTY_STORAGE):
            dir_uid = uuid.UUID(entry.clsid)
            hasher.update(dir_uid.bytes_le)
<<<<<<< HEAD

        if entry.entry_type == STGTY_STREAM:
            hasher.update(entry.size.to_bytes(4, "little"))

        # TODO: empty in our case, to check with a msi with flags set
        hasher.update(entry.dwUserFlags.to_bytes(4, "little"))

        if entry.entry_type != STGTY_ROOT:
            hasher.update(entry.createTime.to_bytes(8, "little"))
            hasher.update(entry.modifyTime.to_bytes(8, "little"))
=======
        
        if entry.entry_type == STGTY_STREAM:
            hasher.update(entry.size.to_bytes(4, 'little'))
        
        hasher.update(entry.dwUserFlags.to_bytes(4, 'little'))  # TODO empty in our case, to check with a msi with flags set

        if entry.entry_type != STGTY_ROOT:
            hasher.update(entry.createTime.to_bytes(8, 'little'))
            hasher.update(entry.modifyTime.to_bytes(8, 'little'))

        return

    def _calculate_prehash(self, digest_algorithm: HashFunction) -> bytes:
        prehasher = digest_algorithm()
        SignedMsiFile._prehash_entry(self._ole_file.root, prehasher)
        
        entries = self._ole_file.root.kids  # TODO handle nested kids
        entries.sort(key=attrgetter('name_utf16'))
        for entry in entries:
            if entry.name in ("\x05DigitalSignature", '\x05MsiDigitalSignatureEx'):
                continue
            SignedMsiFile._prehash_entry(entry, prehasher)
        return prehasher.digest()
>>>>>>> c524ab5 (Add support for msi #24)
