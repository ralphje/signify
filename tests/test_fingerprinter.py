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
import os.path
import pathlib
import unittest

from signify.fingerprinter import (
    AuthenticodeFingerprinter,
    Finger,
    Fingerprinter,
    Range,
)

root_dir = pathlib.Path(__file__).parent


class FingerPrinterTestCase(unittest.TestCase):
    maxDiff = None

    def test_entire_blobs(self):
        for filename in (root_dir / "test_data").iterdir():
            if str(filename).endswith(".res") or not os.path.exists(
                str(filename) + ".res"
            ):
                continue
            with self.subTest(filename):
                with open(str(filename), "rb") as file_obj:
                    fingerprinter = AuthenticodeFingerprinter(file_obj)
                    fingerprinter.add_hashers(
                        hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512
                    )
                    fingerprinter.add_authenticode_hashers(
                        hashlib.md5, hashlib.sha1, hashlib.sha256
                    )
                    results = fingerprinter.hashes()

                # convert to hex
                for v in results.values():
                    for k, b in v.items():
                        v[k] = b.hex()

                with open(str(filename) + ".res") as res_obj:
                    expected_results = json.load(res_obj)

                self.assertDictEqual(expected_results, results)

    def test_reasonable_interval(self):
        # Check if the limit on maximum blocksize for processing still holds.
        dummy = io.BytesIO(b"")
        fp = Fingerprinter(dummy)
        fp._fingers.append(Finger([], [Range(0, 1000001)], ""))

        start, stop = fp._next_interval
        self.assertEqual(0, start)
        self.assertEqual(1000000, stop)

    def test_adjustments(self):
        fp = Fingerprinter(io.BytesIO(b""))
        fp._fingers.append(Finger([], [Range(10, 20)], ""))

        # The remaining range should not yet be touched...
        fp._consume(9, 10)
        self.assertEqual([Range(10, 20)], fp._fingers[0]._ranges)
        # Trying to consume into the range. Blow up.
        self.assertRaises(RuntimeError, fp._consume, 9, 11)
        # We forgot a byte. Blow up.
        self.assertRaises(RuntimeError, fp._consume, 11, 12)
        # Consume a byte
        fp._consume(10, 11)
        self.assertEqual([Range(11, 20)], fp._fingers[0]._ranges)
        # Consumed too much. Blow up.
        self.assertRaises(RuntimeError, fp._consume, 11, 21)
        # Consume exactly.
        fp._consume(11, 20)
        self.assertEqual(0, len(fp._fingers[0]._ranges))

    def test_hash_block(self):
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
        self.assertEqual(hasher.seen, dummy)
