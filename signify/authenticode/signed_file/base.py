from __future__ import annotations

import hashlib
import logging
import os
import pathlib
from collections.abc import Iterable, Iterator
from typing import Any, BinaryIO, Literal

from typing_extensions import Self

from signify._typing import HashFunction
from signify.asn1.hashing import ACCEPTED_DIGEST_ALGORITHMS
from signify.authenticode.signed_data import (
    AuthenticodeSignedData,
)
from signify.authenticode.verification_result import AuthenticodeVerificationResult
from signify.exceptions import (
    AuthenticodeFingerprintNotProvidedError,
    AuthenticodeNotSignedError,
    ParseError,
)
from signify.x509 import Certificate

logger = logging.getLogger(__name__)


class AuthenticodeFile:
    """An Authenticode-signed file that is to be parsed to find the relevant
    sections for Authenticode parsing.
    """

    @classmethod
    def from_stream(
        cls, file_obj: BinaryIO, file_name: str | None = None
    ) -> AuthenticodeFile:
        """This initializer will return a concrete subclass that is compatible with the
        provided file object, and otherwise throw an error.

        The optional ``file_name`` argument can be used to specify the file name.
        """
        if file_name is None and hasattr(file_obj, "name"):
            file_name = pathlib.Path(file_obj.name).name

        # Peek for the first 8 bytes
        file_obj.seek(0, os.SEEK_SET)
        header = file_obj.read(8)
        file_obj.seek(0, os.SEEK_SET)

        for subclass in cls.__subclasses__():
            try:
                attempt = subclass._try_open(file_obj, file_name, header)
            except Exception as e:  # noqa: PERF203
                logger.debug(f"Error while trying {subclass.__name__}: {e!r}")
            else:
                if attempt is not None:
                    return attempt

        raise ParseError("Unable to determine file type with available parsers.")

    @classmethod
    def _try_open(
        cls, file_obj: BinaryIO, file_name: str | None, header: bytes
    ) -> Self | None:
        """Returns a specific :class:`AuthenticodeFile` object for the specified file,
        if compatible, or :const:`None` otherwise. Errors are silently ignored by
        :meth:`from_stream`.

        Since most files will use the header for detection, a header of at least 8
        bytes is provided for convenience.
        """
        return None

    @property
    def signed_datas(self) -> Iterator[AuthenticodeSignedData]:
        """Returns an iterator over :class:`AuthenticodeSignedData` objects relevant for
        this file. See :meth:`iter_signed_datas`
        """

        yield from self.iter_signed_datas()

    def iter_signed_datas(
        self, *, include_nested: bool = True, ignore_parse_errors: bool = True
    ) -> Iterator[AuthenticodeSignedData]:
        """Returns an iterator over :class:`AuthenticodeSignedData` objects relevant
        for this Authenticode-signed file.

        :param include_nested: Boolean, if True, will also iterate over all nested
            SignedData structures
        :param ignore_parse_errors: Indicates how to handle
            :exc:`ParseError` that may be raised while fetching
            embedded :class:`AuthenticodeSignedData` structures.

            When :const:`True`,  which is the default and seems to be how Windows
            handles this as well, this will fetch as many valid
            :class:`AuthenticodeSignedData` structures until an exception
            occurs.

            Note that this will also silence the :exc:`ParseError` that occurs
            when there's no valid :class:`AuthenticodeSignedData` to fetch.

            When :const:`False`, this will raise the :exc:`ParseError` as
            soon as one occurs.
        :raises ParseError: For parse errors in the signed file
        :raises signify.authenticode.AuthenticodeParseError: For parse errors in the
            SignedData
        :return: iterator of signify.authenticode.SignedData
        """
        raise NotImplementedError

    def verify(
        self,
        *,
        multi_verify_mode: Literal["any", "first", "all", "best"] = "any",
        expected_hashes: dict[str, bytes] | None = None,
        ignore_parse_errors: bool = True,
        **kwargs: Any,
    ) -> list[tuple[AuthenticodeSignedData, Iterable[list[Certificate]]]]:
        """Verifies the SignedData structures. This is a little bit more efficient than
        calling all verify-methods separately.

        :param expected_hashes: When provided, should be a mapping of hash names to
            digests. This could speed up the verification process.
        :param multi_verify_mode: Indicates how to verify when there are multiple
            :class:`AuthenticodeSignedData` objects in this file. Can be:

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
        :param ignore_parse_errors: Indicates how to handle :exc:`ParseError`
            that may be raised during parsing of the signed file's certificate table.

            When :const:`True`, which is the default and seems to be how Windows
            handles this as well, this will verify based on all available
            :class:`AuthenticodeSignedData` before a parse error occurs.

            :exc:`AuthenticodeNotSignedError` will be raised when no valid
            :class:`AuthenticodeSignedData` exists.

            When :const:`False`, this will raise the :exc:`ParseError` as soon
            as one occurs. This often occurs before :exc:`AuthenticodeNotSignedError`
            is potentially raised.
        :return: the used structure(s) in validation, as a list of tuples, in the form
            (signed data object, certificate chain)
        :raises AuthenticodeVerificationError: when the verification failed
        :raises ParseError: for parse errors in the signed file
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
    ) -> tuple[AuthenticodeVerificationResult, Exception | None]:
        """This will return a value indicating the signature status of this PE file.
        This will not raise an error when the verification fails, but rather
        indicate this through the resulting enum

        :rtype: (signify.authenticode.AuthenticodeVerificationResult, Exception)
        :returns: The verification result, and the exception containing
            more details (if available or None)
        """

        return AuthenticodeVerificationResult.call(self.verify, *args, **kwargs)

    @classmethod
    def _get_needed_hashes(
        cls,
        signed_datas: Iterable[AuthenticodeSignedData],
        expected_hashes: dict[str, bytes],
    ) -> set[HashFunction]:
        """Provided the list of signed datas and already-provided hashes, returns a
        list of hashes that need to be calculated.

        Calculates the expected hashes that are needed for verification. This
        provides a small speed-up by pre-calculating all hashes, so that not each
        individual SignerInfo object is responsible for calculating their own hash.

        :param signed_datas: The signed datas of this object. Provided to allow
            :meth:`verify` to prefetch these
        :param expected_hashes: Hashes provided by the caller of :meth:`verify`
        :return: All required hashes
        """

        # Calculate which hashes we require for the signedinfos
        digest_algorithms = set()
        for signed_data in signed_datas:
            digest_algorithms.add(signed_data.digest_algorithm)

        # Calculate which hashes are needed
        provided_hashes = {getattr(hashlib, t) for t in expected_hashes}
        return digest_algorithms - provided_hashes

    def get_fingerprint(self, digest_algorithm: HashFunction) -> bytes:
        """Gets the fingerprint for this file"""
        raise AuthenticodeFingerprintNotProvidedError(
            f"Fingerprint for digest algorithm {digest_algorithm.__name__} could not "
            "be calculated and was not provided as pre-calculated expected hash."
        )

    def _calculate_expected_hashes(
        self,
        signed_datas: Iterable[AuthenticodeSignedData],
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

        # Calculate the needed hashes
        for digest_algorithm in self._get_needed_hashes(signed_datas, expected_hashes):
            fingerprint = self.get_fingerprint(digest_algorithm)
            expected_hashes[digest_algorithm().name] = fingerprint
        return expected_hashes

    def verify_additional_hashes(self, signed_data: AuthenticodeSignedData) -> None:
        """Verifies additional hashes that may be present in the
        :class:`AuthenticodeSignedData` referencing this data. Return :const:`None`
        when the verification succeeds, or raises an error otherwise.

        The default implementation is to do nothing.
        """
        return None
