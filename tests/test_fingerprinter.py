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
import pickle
import unittest
import pathlib

from pesigcheck.fingerprinter import AuthenticodeFingerprinter, Fingerprinter, Finger, Range


class FingerPrinterTestCase(unittest.TestCase):
    def test_entire_blobs(self):
        for filename in pathlib.Path("./test_data").iterdir():
            if str(filename).endswith(".res"):
                continue
            with self.subTest(filename):
                with open(str(filename), "rb") as file_obj:
                    fingerprinter = AuthenticodeFingerprinter(file_obj)
                    fingerprinter.add_hashers(hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512)
                    fingerprinter.add_authenticode_hashers(hashlib.md5, hashlib.sha1, hashlib.sha256)
                    results = fingerprinter.hashes()
                with open(str(filename) + ".res", "rb") as res_obj:
                    expected_results = pickle.load(res_obj)

                self.assertEqual(results, expected_results)

    def test_reasonable_interval(self):
        # Check if the limit on maximum blocksize for processing still holds.
        dummy = io.StringIO("")
        fp = Fingerprinter(dummy)
        fp._fingers.append(Finger(None, [Range(0, 1000001)],  None))

        start, stop = fp._next_interval
        self.assertEquals(0, start)
        self.assertEquals(1000000, stop)

    def test_adjustments(self):
        fp = Fingerprinter(io.StringIO(""))
        fp._fingers.append(Finger(None, [Range(10, 20)], None))

        # The remaining range should not yet be touched...
        fp._consume(9, 10)
        self.assertEquals([Range(10, 20)], fp._fingers[0]._ranges)
        # Trying to consume into the range. Blow up.
        self.assertRaises(RuntimeError, fp._consume, 9, 11)
        # We forgot a byte. Blow up.
        self.assertRaises(RuntimeError, fp._consume, 11, 12)
        # Consume a byte
        fp._consume(10, 11)
        self.assertEquals([Range(11, 20)], fp._fingers[0]._ranges)
        # Consumed too much. Blow up.
        self.assertRaises(RuntimeError, fp._consume, 11, 21)
        # Consume exactly.
        fp._consume(11, 20)
        self.assertEquals(0, len(fp._fingers[0]._ranges))

    def test_hash_block(self):
        # Does it invoke a hash function?
        dummy = "12345"
        fp = Fingerprinter(io.StringIO(dummy))
        big_finger = Finger(None, [Range(0, len(dummy))], None)

        class MockHasher(object):
            def __init__(self):
                self.seen = ""

            def update(self, content):  # pylint: disable-msg=C6409
                self.seen += content

        hasher = MockHasher()

        big_finger.hashers = [hasher]
        fp._fingers.append(big_finger)
        # Let's process the block
        fp._hash_block(dummy, 0, len(dummy))
        self.assertEquals(hasher.seen, dummy)
