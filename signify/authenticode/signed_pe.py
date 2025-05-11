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
from collections.abc import Iterable, Iterator
from functools import cached_property
from typing import BinaryIO, cast

from typing_extensions import TypedDict

from signify import fingerprinter
from signify._typing import HashFunction
from signify.authenticode import structures
from signify.authenticode.signed_file import SignedFile
from signify.exceptions import SignedPEParseError

logger = logging.getLogger(__name__)

RelRange = collections.namedtuple("RelRange", "start length")


class ParsedCertTable(TypedDict):
    revision: int
    type: int
    certificate: bytes


class SignedPEFile(SignedFile):
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

    def _seek_start_of_pe(self) -> int:
        """Seeks in the file to the start of the PE header. After this method,
        the file header should be after ``b"PE\0\0"``.
        """

        # Check if file starts with MZ
        self.file.seek(0, os.SEEK_SET)
        if self.file.read(2) != b"MZ":
            raise SignedPEParseError("MZ header not found")

        # Offset to e_lfanew (which is the PE header) is at 0x3C of the MZ header
        self.file.seek(0x3C, os.SEEK_SET)
        pe_offset = cast(int, struct.unpack("<I", self.file.read(4))[0])
        if pe_offset >= self._filelength:
            raise SignedPEParseError(
                "PE header location is beyond file boundaries"
                f"({pe_offset} >= {self._filelength})"
            )

        # Check if the PE header is PE
        self.file.seek(pe_offset, os.SEEK_SET)
        if self.file.read(4) != b"PE\0\0":
            raise SignedPEParseError("PE header not found")

        return pe_offset

    def _seek_optional_header(self) -> tuple[int, int]:
        """Seeks in the file for the start and size of the optional COFF header.
        After this method, the file header should be at the start of the optional
        header.
        """

        pe_offset = self._seek_start_of_pe()

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

        self.file.seek(optional_header_offset, os.SEEK_SET)
        return optional_header_offset, optional_header_size

    def _parse_pe_header_locations(self) -> dict[str, RelRange]:
        """Parses a PE file to find the sections to exclude from the AuthentiCode hash.

        See http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx for
        information about the structure.
        """

        location = {}
        optional_header_offset, optional_header_size = self._seek_optional_header()

        # The optional header contains the signature of the image
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

    @cached_property
    def page_size(self) -> int:
        """Gets the page size from the optional COFF header, or if not available,
        returns 4096 as best guess.
        """
        optional_header_offset, optional_header_size = self._seek_optional_header()

        if optional_header_size < 36:
            return 4096

        self.file.seek(optional_header_offset + 32, os.SEEK_SET)
        return cast(int, struct.unpack("<I", self.file.read(4))[0])

    def get_fingerprinter(self) -> fingerprinter.AuthenticodeFingerprinter:
        """Returns a fingerprinter object for this file.

        :rtype: signify.fingerprinter.AuthenticodeFingerprinter
        """
        return fingerprinter.AuthenticodeFingerprinter(self.file)

    def get_fingerprint(
        self,
        digest_algorithm: HashFunction,
        start: int = 0,
        end: int = -1,
        aligned: bool = False,
    ) -> bytes:
        """Gets the fingerprint for this file, with the provided start and end,
        and optionally aligned to the PE file's alignment.
        """
        fingerprinter = self.get_fingerprinter()
        fingerprinter.add_authenticode_hashers(
            digest_algorithm,
            start=start,
            end=end,
            block_size=self.page_size if aligned else None,
        )
        return fingerprinter.hash()[digest_algorithm().name]

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
