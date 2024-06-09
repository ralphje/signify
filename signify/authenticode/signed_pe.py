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
import os
import struct
from typing import Any, BinaryIO, Iterable, Iterator

from typing_extensions import Literal, TypedDict

from signify import fingerprinter
from signify.asn1.hashing import ACCEPTED_DIGEST_ALGORITHMS
from signify.authenticode import structures
from signify.exceptions import AuthenticodeNotSignedError, SignedPEParseError
from signify.x509 import Certificate

logger = logging.getLogger(__name__)

RelRange = collections.namedtuple("RelRange", "start length")


class ParsedCertTable(TypedDict):
    revision: int
    type: int
    certificate: bytes


class SignedPEFile:
    def __init__(self, file_obj: BinaryIO):
        """A PE file that is to be parsed to find the relevant sections for
        Authenticode parsing.

        :param file_obj: A PE file opened in binary file
        """

        self.file = file_obj

        self.file.seek(0, os.SEEK_END)
        self._filelength = self.file.tell()

    def get_authenticode_omit_sections(self) -> dict[str, RelRange] | None:
        """Returns all ranges of the raw file that are relevant for exclusion for the
        calculation of the hash function used in Authenticode.

        The relevant sections are (as per
        `<http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx>`_,
        chapter Calculating the PE Image Hash):

        * The location of the checksum
        * The location of the entry of the Certificate Table in the Data Directory
        * The location of the Certificate Table.

        :returns: dict if successful, or None if not successful
        """

        try:
            locations = self._parse_pe_header_locations()
        except (SignedPEParseError, struct.error):
            return None
        return {
            k: v
            for k, v in locations.items()
            if k in ["checksum", "datadir_certtable", "certtable"]
        }

    def _parse_pe_header_locations(self) -> dict[str, RelRange]:
        """Parses a PE file to find the sections to exclude from the AuthentiCode hash.

        See http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx for
        information about the structure.
        """

        location = {}

        # Check if file starts with MZ
        self.file.seek(0, os.SEEK_SET)
        if self.file.read(2) != b"MZ":
            raise SignedPEParseError("MZ header not found")

        # Offset to e_lfanew (which is the PE header) is at 0x3C of the MZ header
        self.file.seek(0x3C, os.SEEK_SET)
        pe_offset = struct.unpack("<I", self.file.read(4))[0]
        if pe_offset >= self._filelength:
            raise SignedPEParseError(
                "PE header location is beyond file boundaries"
                f"({pe_offset} >= {self._filelength})"
            )

        # Check if the PE header is PE
        self.file.seek(pe_offset, os.SEEK_SET)
        if self.file.read(4) != b"PE\0\0":
            raise SignedPEParseError("PE header not found")

        # The COFF header contains the size of the optional header
        self.file.seek(pe_offset + 20, os.SEEK_SET)
        optional_header_size = struct.unpack("<H", self.file.read(2))[0]
        optional_header_offset = pe_offset + 24
        if optional_header_size + optional_header_offset > self._filelength:
            # This is not strictly a failure for windows, but such files better
            # be treated as generic files. They can not be carrying SignedData.
            raise SignedPEParseError(
                f"The optional header exceeds the file length ({optional_header_size} "
                f"+ {optional_header_offset} > {self._filelength})"
            )

        if optional_header_size < 68:
            # We can't do authenticode-style hashing. If this is a valid binary,
            # which it can be, the header still does not even contain a checksum.
            raise SignedPEParseError(
                f"The optional header size is {optional_header_size} < 68, "
                f"which is insufficient for authenticode",
            )

        # The optional header contains the signature of the image
        self.file.seek(optional_header_offset, os.SEEK_SET)
        signature = struct.unpack("<H", self.file.read(2))[0]
        if signature == 0x10B:  # IMAGE_NT_OPTIONAL_HDR32_MAGIC
            rva_base = optional_header_offset + 92  # NumberOfRvaAndSizes
            cert_base = optional_header_offset + 128  # Certificate Table
        elif signature == 0x20B:  # IMAGE_NT_OPTIONAL_HDR64_MAGIC
            rva_base = optional_header_offset + 108  # NumberOfRvaAndSizes
            cert_base = optional_header_offset + 144  # Certificate Table
        else:
            # A ROM image or such, not in the PE/COFF specs. Not sure what to do.
            raise SignedPEParseError(
                "The PE Optional Header signature is %x, which is unknown", signature
            )

        # According to the specification, the checksum should not be hashed.
        location["checksum"] = RelRange(optional_header_offset + 64, 4)

        # Read the RVA
        if optional_header_offset + optional_header_size < rva_base + 4:
            logger.debug(
                "The PE Optional Header size can not accommodate for the"
                " NumberOfRvaAndSizes field"
            )
            return location
        self.file.seek(rva_base, os.SEEK_SET)
        number_of_rva = struct.unpack("<I", self.file.read(4))[0]
        if number_of_rva < 5:
            logger.debug(
                "The PE Optional Header does not have a Certificate Table entry in its"
                " Data Directory; NumberOfRvaAndSizes = %d",
                number_of_rva,
            )
            return location
        if optional_header_offset + optional_header_size < cert_base + 8:
            logger.debug(
                "The PE Optional Header size can not accommodate for a Certificate"
                " Table entry in its Data Directory"
            )
            return location

        # According to the spec, the certificate table entry of the data directory
        # should be omitted
        location["datadir_certtable"] = RelRange(cert_base, 8)

        # Read the certificate table entry of the Data Directory
        self.file.seek(cert_base, os.SEEK_SET)
        address, size = struct.unpack("<II", self.file.read(8))

        if not size:
            logger.debug("The Certificate Table is empty")
            return location

        if (
            address < optional_header_size + optional_header_offset
            or address + size > self._filelength
        ):
            logger.debug(
                "The location of the Certificate Table in the binary makes no sense and"
                " is either beyond the boundaries of the file, or in the middle of the"
                " PE header; VirtualAddress: %x, Size: %x",
                address,
                size,
            )
            return location

        location["certtable"] = RelRange(address, size)
        return location

    def _parse_cert_table(self) -> Iterator[ParsedCertTable]:
        """Parses the Certificate Table, iterates over all certificates"""

        locations = self.get_authenticode_omit_sections()
        if not locations or "certtable" not in locations:
            raise SignedPEParseError(
                "The PE file does not contain a certificate table."
            )

        position = locations["certtable"].start
        certtable_end = sum(locations["certtable"])
        while position < certtable_end:
            # check if this position is viable, we need at least 8 bytes for our header
            if position + 8 > self._filelength:
                raise SignedPEParseError(
                    "Position of certificate table is beyond length of file"
                )
            self.file.seek(position, os.SEEK_SET)
            length = struct.unpack("<I", self.file.read(4))[0]
            revision = struct.unpack("<H", self.file.read(2))[0]
            certificate_type = struct.unpack("<H", self.file.read(2))[0]

            # check if we are not going to perform a negative read (and 0 bytes is
            # weird as well)
            if length <= 8 or position + length > certtable_end:
                raise SignedPEParseError("Invalid length in certificate table header")
            certificate = self.file.read(length - 8)

            yield {
                "revision": revision,
                "type": certificate_type,
                "certificate": certificate,
            }
            position += length + (8 - length % 8) % 8

    def get_fingerprinter(self) -> fingerprinter.AuthenticodeFingerprinter:
        """Returns a fingerprinter object for this file.

        :rtype: signify.fingerprinter.AuthenticodeFingerprinter
        """
        return fingerprinter.AuthenticodeFingerprinter(self.file)

    @property
    def signed_datas(self) -> Iterator[structures.AuthenticodeSignedData]:
        """Returns an iterator over :class:`AuthenticodeSignedData` objects relevant for
        this PE file. See :meth:`iter_signed_datas`
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

        def recursive_nested(
            signed_data: structures.AuthenticodeSignedData,
        ) -> Iterator[structures.AuthenticodeSignedData]:
            yield signed_data
            if include_nested:
                for nested in signed_data.signer_info.nested_signed_datas:
                    yield from recursive_nested(nested)

        try:
            found = False
            for certificate in self._parse_cert_table():
                if certificate["revision"] != 0x200:
                    raise SignedPEParseError(
                        f"Unknown certificate revision {certificate['revision']!r}"
                    )

                if certificate["type"] == 2:
                    yield from recursive_nested(
                        structures.AuthenticodeSignedData.from_envelope(
                            certificate["certificate"], pefile=self
                        )
                    )
                    found = True

            if not found:
                raise SignedPEParseError(
                    "A SignedData structure was not found in the PE file's Certificate"
                    " Table"
                )
        except SignedPEParseError:
            if not ignore_parse_errors:
                raise

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
        if needed_hashes:
            fingerprinter = self.get_fingerprinter()
            fingerprinter.add_authenticode_hashers(*needed_hashes)
            expected_hashes.update(fingerprinter.hashes()["authentihash"])

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
