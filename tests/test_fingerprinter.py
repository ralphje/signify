# This is a derivative, modified, work from the verify-sigs project.
# Please refer to the LICENSE file in the distribution for more
# information. Original filename: generate_test_data.py
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


import hashlib
import io
import json
import pathlib

import pytest

from signify.authenticode.signed_file.pe import SignedPEFingerprinter
from signify.fingerprinter import Finger, Fingerprinter, Range
from tests._utils import open_test_data

fingerprint_results = list(
    json.load(
        (pathlib.Path(__file__).parent / "fingerprint_results.json").open()
    ).items()
)


@pytest.mark.parametrize(("filename", "expected_hashes"), fingerprint_results)
def test_pe_hashes(filename, expected_hashes):
    with open_test_data(filename) as file_obj:
        fingerprinter = SignedPEFingerprinter(file_obj)
        fingerprinter.add_hashers(
            hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512
        )
        fingerprinter.add_signed_pe_hashers(hashlib.md5, hashlib.sha1, hashlib.sha256)
        results = fingerprinter.hashes()

    # convert to hex
    for v in results.values():
        for k, b in v.items():
            v[k] = b.hex()

    assert expected_hashes == results


def test_reasonable_interval():
    # Check if the limit on maximum blocksize for processing still holds.
    dummy = io.BytesIO(b"")
    fp = Fingerprinter(dummy)
    fp._fingers.append(Finger([], [Range(0, 1000001)], ""))

    start, stop = fp._next_interval
    assert start == 0
    assert stop == 1000000


def test_adjustments():
    fp = Fingerprinter(io.BytesIO(b""))
    fp._fingers.append(Finger([], [Range(10, 20)], ""))

    # The remaining range should not yet be touched...
    fp._consume(9, 10)
    assert [Range(10, 20)] == fp._fingers[0]._ranges
    # Trying to consume into the range. Blow up.
    with pytest.raises(RuntimeError):
        fp._consume(9, 11)
    # We forgot a byte. Blow up.
    with pytest.raises(RuntimeError):
        fp._consume(11, 12)
    # Consume a byte
    fp._consume(10, 11)
    assert [Range(11, 20)] == fp._fingers[0]._ranges
    # Consumed too much. Blow up.
    with pytest.raises(RuntimeError):
        fp._consume(11, 21)
    # Consume exactly.
    fp._consume(11, 20)
    assert len(fp._fingers[0]._ranges) == 0


def test_hash_block():
    # Does it invoke a hash function?
    dummy = b"12345"
    fp = Fingerprinter(io.BytesIO(dummy))
    big_finger = Finger([], [Range(0, len(dummy))], "")

    class MockHasher:
        def __init__(self):
            self.seen = b""

        def update(self, content):  # pylint: disable-msg=C6409
            self.seen += content

    hasher = MockHasher()

    big_finger.hashers = [hasher]
    fp._fingers.append(big_finger)
    # Let's process the block
    fp._hash_block(dummy, 0, len(dummy))
    assert hasher.seen == dummy
