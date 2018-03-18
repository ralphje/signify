# This is a derivative, modified, work from the verify-sigs project.
# Please refer to the LICENSE file in the distribution for more
# information. Original filename: auth_data_test.py
#
# Parts of this file are licensed as follows:
#
# Copyright 2012 Google Inc. All Rights Reserved.
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
import unittest
import pathlib

import binascii

from pesigcheck.fingerprinter import AuthenticodeFingerprinter
from pesigcheck.signed_pe import SignedPEFile


class AuthenticodeParserTestCase(unittest.TestCase):
    def test_software_update(self):
        with open(str(pathlib.Path("./test_data/SoftwareUpdate.exe")), "rb") as f:
            fingerprinter = AuthenticodeFingerprinter(f)
            fingerprinter.add_authenticode_hashers(hashlib.sha1)
            hashes = fingerprinter.hash()

            # Sanity check that the authenticode hash is still correct
            self.assertEqual(binascii.hexlify(hashes['sha1']).decode('ascii'),
                             '978b90ace99c764841d2dd17d278fac4149962a3')

            pefile = SignedPEFile(f)

            # This should not raise any errors.
            signed_datas = list(pefile.get_signed_datas())
            # There may be multiple of these, if the windows binary was signed multiple
            # times, e.g. by different entities. Each of them adds a complete SignedData
            # blob to the binary. For our sample, there is only one blob.
            self.assertEqual(len(signed_datas), 1)
            signed_data = signed_datas[0]

            self.assertEqual(signed_data._rest_data, b'\0')

            # TODO: Test that validation succeeds
            # auth.ValidateHashes(computed_content_hash)
            # auth.ValidateSignatures()
            # auth.ValidateCertChains(time.gmtime())
