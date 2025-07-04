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

from __future__ import annotations

import binascii
import collections
import hashlib
import logging
import os
import pathlib
import sys
from typing import BinaryIO

from signify._typing import HashFunction
from signify.authenticode import signed_pe

logger = logging.getLogger(__name__)

Range = collections.namedtuple("Range", "start end")
"""A range with a start and an end."""


class Finger:
    """A Finger defines how to hash a file to get specific fingerprints.

    The Finger contains one or more hash functions, a set of ranges in the file that
    are to be processed with these hash functions, and a description.

    While one Finger provides potentially multiple hashers, they all get fed the
    same ranges of the file.
    """

    def __init__(
        self,
        hashers: list[hashlib._Hash],
        ranges: list[Range],
        description: str,
        block_size: int | None = None,
    ):
        """

        :param hashers: A list of hashers to feed.
        :param ranges: A list of Ranges that are hashed.
        :param description: The description of this Finger.
        :param block_size: Defines a virtual block size that should be used to
            complement the provided ranges with NULL bytes.
        """

        self._ranges = ranges
        self.hashers = hashers
        self.description = description
        self.block_size = block_size

        self._virtual_range = self._ranges[-1].end - self._ranges[0].start

    @property
    def current_range(self) -> Range | None:
        """The working range of this Finger. Returns None if there is none."""
        if self._ranges:
            return self._ranges[0]
        return None

    def consume(self, start: int, end: int) -> None:
        """Consumes an entire range, or part thereof.

        If the finger has no ranges left, or the current range start is higher than
        the end of the consumed block, nothing happens. Otherwise, the current range is
        adjusted for the consumed block, or removed, if the entire block is consumed.
        For things to work, the consumed range and the current finger starts must be
        equal, and the length of the consumed range may not exceed the length of the
        current range.

        :param start: Beginning of range to be consumed.
        :param end: First offset after the consumed range (end + 1).
        :raises RuntimeError: if the start position of the consumed range is higher
            than the start of the current range in the finger, or if the consumed
            range cuts across block boundaries.
        """

        old = self.current_range
        if old is None:
            return

        if old.start > start:
            if old.start < end:
                raise RuntimeError("Block end too high.")
            return
        if old.start < start:
            raise RuntimeError("Block start too high.")
        if old.end == end:
            del self._ranges[0]
        elif old.end > end:
            self._ranges[0] = Range(end, old.end)
        else:
            raise RuntimeError("Block length exceeds range.")

    def update(self, block: bytes) -> None:
        """Given a data block, feed it to all the registered hashers."""

        for hasher in self.hashers:
            hasher.update(block)

    def update_block_size(self) -> None:
        """Feed the hashes NULL bytes to ensure that a certain (virtual) block size is
        read. Note that this is calculated by using the first offset in the provided
        ranges, and the last offset in the provided ranges, and not the actual amount
        of bytes read.
        """
        if self.block_size is None or (self._virtual_range % self.block_size) == 0:
            return

        self.update(b"\0" * (self.block_size - (self._virtual_range % self.block_size)))


class Fingerprinter:
    def __init__(self, file_obj: BinaryIO, block_size: int = 1000000):
        """A Fingerprinter is an interface to generate hashes of (parts) of a file.

        It is passed in a file object and given a set of :class:`Finger` s that define
        how a file must be hashed. It is a generic approach to not hashing parts of a
        file.

        :param file_obj: A file opened in bytes-mode
        :param block_size: The block size used to feed to the hashers.
        """

        self.file = file_obj
        self.block_size = block_size

        self.file.seek(0, os.SEEK_END)
        self._filelength = self.file.tell()

        self._fingers: list[Finger] = []

    def _adjust_ranges(
        self, ranges: list[Range], start: int = 0, end: int = -1
    ) -> list[Range]:
        """Adjusts provided ranges to all be between the provided start and end
        intervals.

        :param ranges: A list of Ranges to limit between start and end.
        :param start: The start interval for the ranges to be limited to.
        :param end: The end interval for the ranges to be limited to. If negative,
            equals to the end of the file.
        """
        if end < 0:
            end = self._filelength

        result = []
        for range in ranges:
            if range.end < start or range.start > end:
                # ignore any ranges that are outside of the allowed range
                continue
            if range.start >= start and range.end <= end:
                # directly append anything that is within the provided range
                result.append(range)
            else:
                # otherwise, only append the limited range for the provided range
                result.append(
                    Range(
                        max(start, range.start),
                        min(end, range.end),
                    )
                )
        return result

    def add_hashers(
        self,
        *hashers: HashFunction,
        ranges: list[Range] | None = None,
        description: str = "generic",
        start: int = 0,
        end: int = -1,
        block_size: int | None = None,
    ) -> None:
        """Add hash methods to the fingerprinter.

        :param hashers: A list of hashers to add to the Fingerprinter. This generally
            will be hashlib functions.
        :param ranges: A list of Range objects that the hashers should hash. If set
            to :const:`None`, it is set to the entire file.
        :param description: The name for the hashers. This name will return in
            :meth:`hashes`
        :param start: Beginning of range to be hashed, limiting the provided ranges to
            the provided value.
        :param end: End of range to be hashed. If -1, this is equal to the entire file.
        :param block_size: When set, adds NULL bytes to the end of the range to ensure
            a certain block size is read.
        """
        concrete_hashers = [x() for x in hashers]
        if not ranges:
            ranges = [Range(0, self._filelength)]

        finger = Finger(
            concrete_hashers,
            self._adjust_ranges(ranges, start, end),
            description,
            block_size,
        )
        self._fingers.append(finger)

    @property
    def _next_interval(self) -> Range | None:
        """Returns the next Range of the file that is to be hashed.

        For all fingers, inspect their next expected range, and return the
        lowest uninterrupted range of interest. If the range is larger than
        self.block_size, truncate it.

        :returns: Next range of interest in a Range namedtuple.
        """
        starts = {x.current_range.start for x in self._fingers if x.current_range}
        ends = {x.current_range.end for x in self._fingers if x.current_range}

        if not starts:
            return None

        min_start = min(starts)
        starts.remove(min_start)
        ends |= starts

        min_end = min(ends)
        if min_end - min_start > self.block_size:
            min_end = min_start + self.block_size
        return Range(min_start, min_end)

    def _hash_block(self, block: bytes, start: int, end: int) -> None:
        """Feed data blocks into the hashers of fingers.

        This function must be called before adjusting fingers for next
        interval, otherwise the lack of remaining ranges will cause the
        block not to be hashed for a specific finger.

        Start and end are used to validate the expected ranges, to catch
        unexpected use of that logic.

        :param block: The data block.
        :param start: Beginning offset of this block.
        :param end: Next byte after the block.
        :raises RuntimeError: If the provided and expected ranges don't match.
        """
        for finger in self._fingers:
            expected_range = finger.current_range
            if expected_range is None:
                continue
            if (
                start > expected_range.start
                or (start == expected_range.start and end > expected_range.end)
                or (start < expected_range.start < end)
            ):
                raise RuntimeError("Cutting across fingers.")
            if start == expected_range.start:
                finger.update(block)

    def _consume(self, start: int, end: int) -> None:
        for finger in self._fingers:
            finger.consume(start, end)

    def hashes(self) -> dict[str, dict[str, bytes]]:
        """Finalizing function for the Fingerprint class.

        This method applies all the different hash functions over the previously
        specified different ranges of the input file, and computes the resulting hashes.

        After calling this function, the state of the object is reset to its  initial
        state, with no fingers defined.

        :returns: A dict of dicts, the outer dict being a mapping of the description
            (as set in :meth:`add_hashers` and the inner dict being a mapping of hasher
            name to digest.
        :raises RuntimeError: when internal inconsistencies occur.
        """
        while True:
            interval = self._next_interval
            if interval is None:
                break
            self.file.seek(interval.start, os.SEEK_SET)
            block = self.file.read(interval.end - interval.start)
            if len(block) != interval.end - interval.start:
                raise RuntimeError("Short read on file.")
            self._hash_block(block, interval.start, interval.end)
            self._consume(interval.start, interval.end)

        results = {}
        for finger in self._fingers:
            leftover = finger.current_range
            if leftover and (
                len(finger._ranges) > 1
                or leftover.start != self._filelength
                or leftover.end != self._filelength
            ):
                raise RuntimeError("Non-empty range remains.")

            finger.update_block_size()

            res = {}
            for hasher in finger.hashers:
                res[hasher.name] = hasher.digest()
            results[finger.description] = res

        # Clean out things for a fresh start (on the same file object).
        self._fingers = []
        return results

    def hash(self) -> dict[str, bytes]:
        """Very similar to :meth:`hashes`, but only returns a single dict of hash names
        to digests.

        This method can only be called when the :meth:`add_hashers` method was called
        exactly once.
        """
        hashes = self.hashes()
        if len(hashes) != 1:
            raise RuntimeError("Can't return a single hash, use hashes() instead")

        return next(iter(hashes.values()))
