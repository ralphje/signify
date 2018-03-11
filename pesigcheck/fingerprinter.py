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

import collections
import hashlib
import os
import sys
import logging

import struct

import binascii

logger = logging.getLogger(__name__)

Range = collections.namedtuple('Range', 'start end')
RelRange = collections.namedtuple('RelRange', 'start length')


class Finger(object):
    """A Finger defines how to hash a file to get specific fingerprints.

    The Finger contains one or more hash functions, a set of ranges in the
    file that are to be processed with these hash functions, and relevant
    metadata and accessor methods.

    While one Finger provides potentially multiple hashers, they all get
    fed the same ranges of the file.
    """

    def __init__(self, hashers, ranges, description=None):
        self._ranges = ranges
        self.hashers = hashers
        self.description = description

    @property
    def current_range(self):
        """The working range of this Finger. Returns None if there is none."""
        if self._ranges:
            return self._ranges[0]
        return None

    def consume(self, start, end):
        """Consumes an entire range, or part thereof.

        If the finger has no ranges left, or the curent range start is higher
        than the end of the consumed block, nothing happens. Otherwise,
        the current range is adjusted for the consumed block, or removed,
        if the entire block is consumed. For things to work, the consumed
        range and the current finger starts must be equal, and the length
        of the consumed range may not exceed the length of the current range.

        Args:
          start: Beginning of range to be consumed.
          end: First offset after the consumed range (end + 1).

        Raises:
          RuntimeError: if the start position of the consumed range is
              higher than the start of the current range in the finger, or if
              the consumed range cuts accross block boundaries.
        """

        old = self.current_range
        if old is None:
            return

        if old.start > start:
            if old.start < end:
                raise RuntimeError('Block end too high.')
            return
        if old.start < start:
            raise RuntimeError('Block start too high.')
        if old.end == end:
            del (self._ranges[0])
        elif old.end > end:
            self._ranges[0] = Range(end, old.end)
        else:
            raise RuntimeError('Block length exceeds range.')

    def update(self, block):
        """Given a data block, feed it to all the registered hashers."""

        for hasher in self.hashers:
            hasher.update(block)


class Fingerprinter(object):
    def __init__(self, file_obj, block_size=1000000):
        self.file = file_obj
        self.block_size = block_size

        self.file.seek(0, os.SEEK_END)
        self._filelength = self.file.tell()

        self._fingers = []

    def add_hashers(self, *hashers, ranges=None, description="generic"):
        hashers = [x() for x in hashers]
        if not ranges:
            ranges = [Range(0, self._filelength)]

        finger = Finger(hashers, ranges, description)
        self._fingers.append(finger)

    @property
    def _next_interval(self):
        """Returns the next Range of the file that is to be hashed.

        For all fingers, inspect their next expected range, and return the
        lowest uninterrupted range of interest. If the range is larger than
        self.block_size, truncate it.

        Returns:
          Next range of interest in a Range namedtuple.
        """
        starts = set([x.current_range.start for x in self._fingers if x.current_range])
        ends = set([x.current_range.end for x in self._fingers if x.current_range])

        if not starts:
            return None

        min_start = min(starts)
        starts.remove(min_start)
        ends |= starts

        min_end = min(ends)
        if min_end - min_start > self.block_size:
            min_end = min_start + self.block_size
        return Range(min_start, min_end)

    def _hash_block(self, block, start, end):
        """_HashBlock feeds data blocks into the hashers of fingers.

        This function must be called before adjusting fingers for next
        interval, otherwise the lack of remaining ranges will cause the
        block not to be hashed for a specific finger.

        Start and end are used to validate the expected ranges, to catch
        unexpected use of that logic.

        Args:
          block: The data block.
          start: Beginning offset of this block.
          end: Offset of the next byte after the block.

        Raises:
          RuntimeError: If the provided and expected ranges don't match.
        """
        for finger in self._fingers:
            expected_range = finger.current_range
            if expected_range is None:
                continue
            if start > expected_range.start or \
                    (start == expected_range.start and end > expected_range.end) or \
                    (start < expected_range.start < end):
                raise RuntimeError('Cutting across fingers.')
            if start == expected_range.start:
                finger.update(block)

    def _consume(self, start, end):
        for finger in self._fingers:
            finger.consume(start, end)

    def hashes(self):
        """Finalizing function for the Fingerprint class.

        This method applies all the different hash functions over the
        previously specified different ranges of the input file, and
        computes the resulting hashes.

        After calling HashIt, the state of the object is reset to its
        initial state, with no fingers defined.

        Returns:
            A dict of dicts, with each dict containing name of fingerprint
            type, names of hashes and values

        Raises:
           RuntimeError: when internal inconsistencies occur.
        """
        while True:
            interval = self._next_interval
            if interval is None:
                break
            self.file.seek(interval.start, os.SEEK_SET)
            block = self.file.read(interval.end - interval.start)
            if len(block) != interval.end - interval.start:
                raise RuntimeError('Short read on file.')
            self._hash_block(block, interval.start, interval.end)
            self._consume(interval.start, interval.end)

        results = {}
        for finger in self._fingers:
            leftover = finger.current_range
            if leftover:
                if len(finger.ranges) > 1 or leftover.start != self._filelength or leftover.end != self._filelength:
                    raise RuntimeError('Non-empty range remains.')

            res = {}
            for hasher in finger.hashers:
                res[hasher.name] = hasher.digest()
            results[finger.description] = res

        # Clean out things for a fresh start (on the same file object).
        self._fingers = []
        return results

    def hash(self):
        hashes = self.hashes()
        if len(hashes) >= 2:
            raise RuntimeError("Can't return a single hash, use hashes() instead")

        return list(hashes.values())[0]


class AuthenticodeFingerprinter(Fingerprinter):
    def _get_authenticode_omit_ranges(self):
        """Parses a PE file to find the sections to exclude from the AuthentiCode hash.

        See http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx for information about the structure.
        """

        omit = {}

        # Check if file starts with MZ
        self.file.seek(0, os.SEEK_SET)
        if self.file.read(2) != b'MZ':
            logger.debug("MZ header not found")
            return None

        # Offset to e_lfanew (which is the PE header) is at 0x3C of the MZ header
        self.file.seek(0x3C, os.SEEK_SET)
        pe_offset = struct.unpack('<I', self.file.read(4))[0]
        if pe_offset >= self._filelength:
            logger.debug("PE header location is beyond file boundaries (%d >= %d)", pe_offset, self._filelength)
            return None

        # Check if the PE header is PE
        self.file.seek(pe_offset, os.SEEK_SET)
        if self.file.read(4) != b'PE\0\0':
            logger.debug("PE header not found")
            return None

        # The COFF header contains the size of the optional header
        self.file.seek(pe_offset + 20, os.SEEK_SET)
        optional_header_size = struct.unpack('<H', self.file.read(2))[0]
        optional_header_offset = pe_offset + 24
        if optional_header_size + optional_header_offset > self._filelength:
            # This is not strictly a failure for windows, but such files better
            # be treated as generic files. They can not be carrying SignedData.
            logger.warning("The optional header exceeds the file length (%d + %d > %d)",
                           optional_header_size, optional_header_offset, self._filelength)
            return None

        if optional_header_size < 68:
            # We can't do authenticode-style hashing. If this is a valid binary,
            # which it can be, the header still does not even contain a checksum.
            logger.warning("The optional header size is %d < 68, which is insufficient for authenticode",
                           optional_header_size)
            return None

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
            logger.warning("The PE Optional Header signature is %x, which is unknown", signature)
            return None

        # According to the specification, the checksum should not be hashed.
        omit['checksum'] = RelRange(optional_header_offset + 64, 4)

        # Read the RVA
        if optional_header_size + optional_header_size < rva_base + 4:
            logger.debug("The PE Optional Header size can not accommodate for the NumberOfRvaAndSizes field")
            return omit
        self.file.seek(rva_base, os.SEEK_SET)
        number_of_rva = struct.unpack('<I', self.file.read(4))[0]
        if number_of_rva < 5:
            logger.debug("The PE Optional Header does not have a Certificate Table entry in its Data Directory; "
                         "NumberOfRvaAndSizes = %d", number_of_rva)
            return omit
        if optional_header_offset + optional_header_size < cert_base + 8:
            logger.debug("The PE Optional Header size can not accommodate for a Certificate Table entry in its Data "
                         "Directory")
            return omit

        # According to the spec, the certificate table entry of the data directory should be omitted
        omit['certtable'] = RelRange(cert_base, 8)

        # Read the certificate table entry of the Data Directory
        self.file.seek(cert_base, os.SEEK_SET)
        address, size = struct.unpack('<II', self.file.read(8))

        if not size:
            logger.debug("The Certificate Table is empty")
            return omit

        if address < optional_header_size + optional_header_offset or address + size > self._filelength:
            logger.debug("The location of the Certificate Table in the binary makes no sense and is either beyond the "
                         "boundaries of the file, or in the middle of the PE header; "
                         "VirtualAddress: %x, Size: %x", address, size)
            return omit

        omit['signeddata'] = RelRange(address, size)
        return omit

    def add_authenticode_hashers(self, *hashers):
        try:
            omit = self._get_authenticode_omit_ranges()
        except struct.error:
            logger.warning("Parsing PE header failed, assuming it is not a valid header")
            omit = None

        if omit is None:
            return False

        ranges = []
        start = 0
        for start_length in sorted(omit.values()):
            ranges.append(Range(start, start_length.start))
            start = sum(start_length)
        ranges.append(Range(start, self._filelength))

        self.add_hashers(*hashers, ranges=ranges, description='authentihash')
        return True


def main(*filenames):
    for filename in filenames:
        print("{}:".format(filename))
        with open(filename, "rb") as file_obj:
            fingerprinter = AuthenticodeFingerprinter(file_obj)
            fingerprinter.add_hashers(hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512)
            fingerprinter.add_authenticode_hashers(hashlib.md5, hashlib.sha1, hashlib.sha256)
            results = fingerprinter.hashes()

            for description, result in sorted(results.items()):
                print("  {}:".format(description or "generic"))

                for k, v in sorted(result.items()):
                    if k == "_":
                        continue
                    print("    {k:<10}: {v}".format(k=k, v=binascii.hexlify(v).decode("ascii")))


if __name__ == '__main__':
    main(*sys.argv[1:])
