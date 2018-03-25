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

"""This module effectively implements the relevant parts of the PECOFF_ documentation to find the relevant parts of the
PE structure.

It is also capable of listing all the certificates in the Certificate Table and find the certificate with type 0x2.
The actual parsing of this certificate is perfomed by :mod:`signify.authenticode`.

.. _PECOFF: http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
"""

import collections
import logging
import os
import struct
import sys

logger = logging.getLogger(__name__)

RelRange = collections.namedtuple('RelRange', 'start length')


class SignedPEParseError(Exception):
    pass


class SignedPEFile(object):
    def __init__(self, file_obj):
        """A PE file that is to be parsed to find the relevant sections for Authenticode parsing.

        :param file_obj: A PE file opened in binary file
        """

        self.file = file_obj

        self.file.seek(0, os.SEEK_END)
        self._filelength = self.file.tell()

    def get_authenticode_omit_sections(self):
        """Returns all ranges of the raw file that are relevant for exclusion for the calculation of the hash
        function used in Authenticode.

        The relevant sections are (as per Authenticode_PE_, chapter Calculating the PE Image Hash):

        * The location of the checksum
        * The location of the entry of the Certificate Table in the Data Directory
        * The location of the Certificate Table.

        .. _Authenticode_PE: http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx

        :returns: dict if successful, or None if not successful
        """

        try:
            locations = self._parse_pe_header_locations()
        except (SignedPEParseError, struct.error):
            return None
        return {k: v for k, v in locations.items() if k in ['checksum', 'datadir_certtable', 'certtable']}

    def _parse_pe_header_locations(self):
        """Parses a PE file to find the sections to exclude from the AuthentiCode hash.

        See http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx for information about the structure.
        """

        location = {}

        # Check if file starts with MZ
        self.file.seek(0, os.SEEK_SET)
        if self.file.read(2) != b'MZ':
            raise SignedPEParseError("MZ header not found")

        # Offset to e_lfanew (which is the PE header) is at 0x3C of the MZ header
        self.file.seek(0x3C, os.SEEK_SET)
        pe_offset = struct.unpack('<I', self.file.read(4))[0]
        if pe_offset >= self._filelength:
            raise SignedPEParseError("PE header location is beyond file boundaries (%d >= %d)" %
                                     (pe_offset, self._filelength))

        # Check if the PE header is PE
        self.file.seek(pe_offset, os.SEEK_SET)
        if self.file.read(4) != b'PE\0\0':
            raise SignedPEParseError("PE header not found")

        # The COFF header contains the size of the optional header
        self.file.seek(pe_offset + 20, os.SEEK_SET)
        optional_header_size = struct.unpack('<H', self.file.read(2))[0]
        optional_header_offset = pe_offset + 24
        if optional_header_size + optional_header_offset > self._filelength:
            # This is not strictly a failure for windows, but such files better
            # be treated as generic files. They can not be carrying SignedData.
            raise SignedPEParseError("The optional header exceeds the file length (%d + %d > %d)" %
                                     (optional_header_size, optional_header_offset, self._filelength))

        if optional_header_size < 68:
            # We can't do authenticode-style hashing. If this is a valid binary,
            # which it can be, the header still does not even contain a checksum.
            raise SignedPEParseError("The optional header size is %d < 68, which is insufficient for authenticode",
                                     optional_header_size)

        # The optional header contains the signature of the image
        self.file.seek(optional_header_offset, os.SEEK_SET)
        signature = struct.unpack('<H', self.file.read(2))[0]
        if signature == 0x10b:  # IMAGE_NT_OPTIONAL_HDR32_MAGIC
            rva_base = optional_header_offset + 92  # NumberOfRvaAndSizes
            cert_base = optional_header_offset + 128  # Certificate Table
        elif signature == 0x20b:  # IMAGE_NT_OPTIONAL_HDR64_MAGIC
            rva_base = optional_header_offset + 108  # NumberOfRvaAndSizes
            cert_base = optional_header_offset + 144  # Certificate Table
        else:
            # A ROM image or such, not in the PE/COFF specs. Not sure what to do.
            raise SignedPEParseError("The PE Optional Header signature is %x, which is unknown", signature)

        # According to the specification, the checksum should not be hashed.
        location['checksum'] = RelRange(optional_header_offset + 64, 4)

        # Read the RVA
        if optional_header_size + optional_header_size < rva_base + 4:
            logger.debug("The PE Optional Header size can not accommodate for the NumberOfRvaAndSizes field")
            return location
        self.file.seek(rva_base, os.SEEK_SET)
        number_of_rva = struct.unpack('<I', self.file.read(4))[0]
        if number_of_rva < 5:
            logger.debug("The PE Optional Header does not have a Certificate Table entry in its Data Directory; "
                         "NumberOfRvaAndSizes = %d", number_of_rva)
            return location
        if optional_header_offset + optional_header_size < cert_base + 8:
            logger.debug("The PE Optional Header size can not accommodate for a Certificate Table entry in its Data "
                         "Directory")
            return location

        # According to the spec, the certificate table entry of the data directory should be omitted
        location['datadir_certtable'] = RelRange(cert_base, 8)

        # Read the certificate table entry of the Data Directory
        self.file.seek(cert_base, os.SEEK_SET)
        address, size = struct.unpack('<II', self.file.read(8))

        if not size:
            logger.debug("The Certificate Table is empty")
            return location

        if address < optional_header_size + optional_header_offset or address + size > self._filelength:
            logger.debug("The location of the Certificate Table in the binary makes no sense and is either beyond the "
                         "boundaries of the file, or in the middle of the PE header; "
                         "VirtualAddress: %x, Size: %x", address, size)
            return location

        location['certtable'] = RelRange(address, size)
        return location

    def _parse_cert_table(self):
        """Parses the Certificate Table, iterates over all certificates"""

        locations = self._parse_pe_header_locations()
        if 'certtable' not in locations:
            raise SignedPEParseError("The PE file does not contain a certificate table.")

        position = locations['certtable'].start
        while position < sum(locations['certtable']):
            self.file.seek(position, os.SEEK_SET)
            length = struct.unpack('<I', self.file.read(4))[0]
            revision = struct.unpack('<H', self.file.read(2))[0]
            certificate_type = struct.unpack('<H', self.file.read(2))[0]
            certificate = self.file.read(length - 8)

            yield {'revision': revision, 'type': certificate_type, 'certificate': certificate}
            position += length + (8 - (length % 8))

    def get_fingerprinter(self):
        """Returns a fingerprinter object for this file.

        :rtype: signify.fingerprinter.AuthenticodeFingerprinter
        """
        from .fingerprinter import AuthenticodeFingerprinter
        return AuthenticodeFingerprinter(self.file)

    def get_signed_datas(self):
        """Returns a :class:`signify.authenticode_parser.SignedData` object relevant for this PE file.

        :raises SignedPEParseError: For parse errors in the PEFile
        :raises signify.authenticode.AuthenticodeParseError: For parse errors in the SignedData
        :return: iterator of signify.authenticode.SignedData
        """

        from .authenticode import SignedData

        found = False
        for certificate in self._parse_cert_table():
            if certificate['revision'] != 0x200:
                raise SignedPEParseError("Unknown certificate revision %x" % certificate['revision'])

            if certificate['type'] == 2:
                yield SignedData.from_certificate(certificate['certificate'], pefile=self)
                found = True

        if not found:
            raise SignedPEParseError("A SignedData structure was not found in the PE file's Certificate Table")


def main(*filenames):
    for filename in filenames:
        print("{}:".format(filename))
        with open(filename, "rb") as file_obj:
            try:
                pe = SignedPEFile(file_obj)
                for signed_data in pe.get_signed_datas():
                    print("    Included certificates:")
                    for cert in signed_data.certificates:
                        print("      - Subject: {}".format(cert.subject_dn))
                        print("        Issuer: {}".format(cert.issuer_dn))
                        print("        Serial: {}".format(cert.serial_number))
                        print("        Valid from: {}".format(cert.valid_from))
                        print("        Valid to: {}".format(cert.valid_to))

                    print()
                    print("    Signer:")
                    print("        Issuer: {}".format(signed_data.signer_info.issuer_dn))
                    print("        Serial: {}".format(signed_data.signer_info.serial_number))
                    print("        Program name: {}".format(signed_data.signer_info.program_name))
                    print("        More info: {}".format(signed_data.signer_info.more_info))

                    if signed_data.signer_info.countersigner:
                        print()
                        print("    Countersigner:")
                        print("        Issuer: {}".format(signed_data.signer_info.countersigner.issuer_dn))
                        print("        Serial: {}".format(signed_data.signer_info.countersigner.serial_number))
                        print("        Signing time: {}".format(signed_data.signer_info.countersigner.signing_time))

                    print()
                    try:
                        signed_data.verify()
                        print("    Signature: valid")
                    except Exception as e:
                        print("    Signature: invalid")
                        print("    {}".format(e))

            except Exception as e:
                print("    Error while parsing: " + str(e))


if __name__ == '__main__':
    main(*sys.argv[1:])
