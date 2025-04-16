from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Iterable, Iterator
from functools import cached_property
from operator import attrgetter
from typing import Any, BinaryIO

from olefile.olefile import (
    STGTY_ROOT,
    STGTY_STORAGE,
    STGTY_STREAM,
    OleDirectoryEntry,
    OleFileIO,
    NotOleFileError,
)
from typing_extensions import Literal

from signify._typing import HashFunction
from signify.asn1.hashing import ACCEPTED_DIGEST_ALGORITHMS
from signify.authenticode import structures
from signify.exceptions import AuthenticodeNotSignedError
from signify.x509 import Certificate

logger = logging.getLogger(__name__)


class SignedMsiFile:
    def __init__(self, file_obj: BinaryIO):
        """Msi file

        :param file_obj: An MSI file opened in binary file
        """

        self.file = file_obj

    @cached_property
    def _ole_file(self):
        try:
            return OleFileIO(self.file)
        except NotOleFileError:
            raise AuthenticodeNotSignedError("Not a valid OleFile")

    def get_fingerprint(
        self,
        digest_algorithm: HashFunction,
    ) -> bytes:
        """Gets the fingerprint for this msi file."""
        hasher = digest_algorithm()
        hasher.update(self._calculate_prehash(digest_algorithm))
        entries = self._ole_file.root.kids  # TODO handle nested kids
        entries.sort(key=attrgetter("name_utf16"))
        for entry in entries:
            if entry.name in ("\x05DigitalSignature", "\x05MsiDigitalSignatureEx"):
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

        def recursive_nested(
            signed_data: structures.AuthenticodeSignedData,
        ) -> Iterator[structures.AuthenticodeSignedData]:
            yield signed_data
            if include_nested:
                for nested in signed_data.signer_info.nested_signed_datas:
                    yield from recursive_nested(nested)

        if not self._ole_file.exists("\x05DigitalSignature"):
            raise ValueError("missing DigitalSignature")
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
    def _prehash_entry(entry: OleDirectoryEntry, hasher: "hashlib._Hash") -> None:
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

    def _calculate_prehash(self, digest_algorithm: HashFunction) -> bytes:
        prehasher = digest_algorithm()
        SignedMsiFile._prehash_entry(self._ole_file.root, prehasher)

        entries = self._ole_file.root.kids  # TODO handle nested kids
        entries.sort(key=attrgetter("name_utf16"))
        for entry in entries:
            if entry.name in ("\x05DigitalSignature", "\x05MsiDigitalSignatureEx"):
                continue
            SignedMsiFile._prehash_entry(entry, prehasher)
        return prehasher.digest()
