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
import binascii

from .signed_pe import SignedPEFile

logger = logging.getLogger(__name__)

Range = collections.namedtuple('Range', 'start end')
"""A range with a start and an end."""


class Finger(object):
    """A Finger defines how to hash a file to get specific fingerprints.

    The Finger contains one or more hash functions, a set of ranges in the file that are to be processed with these
    hash functions, and a description.

    While one Finger provides potentially multiple hashers, they all get fed the same ranges of the file.
    """

    def __init__(self, hashers, ranges, description=None):
        """

        :param hashers: A list of hashers to feed.
        :param ranges: A list of Ranges that are hashed.
        :param description: The description of this Finger.
        """

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

        If the finger has no ranges left, or the current range start is higher than the end of the consumed block,
        nothing happens. Otherwise, the current range is adjusted for the consumed block, or removed, if the entire
        block is consumed. For things to work, the consumed range and the current finger starts must be equal, and the
        length of the consumed range may not exceed the length of the current range.

        :param start: Beginning of range to be consumed.
        :param end: First offset after the consumed range (end + 1).
        :raises RuntimeError: if the start position of the consumed range is higher than the start of the current range
                              in the finger, or if the consumed range cuts across block boundaries.
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
        """A Fingerprinter is an interface to generate hashes of (parts) of a file.

        It is passed in a file object and given a set of :class:`Finger`s that define how a file must be hashed. It is a
        generic approach to not hashing parts of a file.

        :param file_obj: A file opened in bytes-mode
        :param block_size: The block size used to feed to the hashers.
        """

        self.file = file_obj
        self.block_size = block_size

        self.file.seek(0, os.SEEK_END)
        self._filelength = self.file.tell()

        self._fingers = []

    def add_hashers(self, *hashers, ranges=None, description="generic"):
        """Add hash methods to the fingerprinter.

        :param hashers: A list of hashers to add to the Fingerprinter. This generally will be hashlib functions.
        :param ranges: A list of Range objects that the hashers should hash. If set to :const:`None`, it is set to the
                       entire file.
        :param description: The name for the hashers. This name will return in :meth:`hashes`
        """
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

        This method applies all the different hash functions over the previously specified different ranges of the
        input file, and computes the resulting hashes.

        After calling this function, the state of the object is reset to its  initial state, with no fingers defined.

        :returns: A dict of dicts, the outer dict being a mapping of the description (as set in :meth:`add_hashers`
                  and the inner dict being a mapping of hasher name to digest.
        :raises RuntimeError: when internal inconsistencies occur.
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
        """Very similar to :meth:`hashes`, but only returns a single dict of hash names to digests.

        This method can only be called when the :meth:`add_hashers` method was called exactly once.
        """
        hashes = self.hashes()
        if len(hashes) != 1:
            raise RuntimeError("Can't return a single hash, use hashes() instead")

        return list(hashes.values())[0]


class AuthenticodeFingerprinter(Fingerprinter):
    """An extension of the :class:`Fingerprinter` class that enables the calculation of authentihashes of PE Files."""

    def add_authenticode_hashers(self, *hashers):
        """Specialized method of :meth:`add_hashers` to add hashers with ranges limited to those that are needed to
        calculate the hash of signed PE Files.
        """

        pefile = SignedPEFile(self.file)
        omit = pefile.get_authenticode_omit_sections()

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
