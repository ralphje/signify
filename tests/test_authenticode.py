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
import io
import unittest
import pathlib

import binascii

import datetime

from signify.authenticode import CERTIFICATE_LOCATION
from signify.context import VerificationContext, FileSystemCertificateStore, CertificateStore
from signify.exceptions import VerificationError, AuthenticodeVerificationError, SignedPEParseError
from signify.fingerprinter import AuthenticodeFingerprinter
from signify.signed_pe import SignedPEFile

root_dir = pathlib.Path(__file__).parent
trusted_certificate_store = FileSystemCertificateStore(location=CERTIFICATE_LOCATION, trusted=True)


class AuthenticodeParserTestCase(unittest.TestCase):
    def test_software_update(self):
        with open(str(root_dir / "test_data" / "SoftwareUpdate.exe"), "rb") as f:
            fingerprinter = AuthenticodeFingerprinter(f)
            fingerprinter.add_authenticode_hashers(hashlib.sha1)
            hashes = fingerprinter.hash()

            # Sanity check that the authenticode hash is still correct
            self.assertEqual(binascii.hexlify(hashes['sha1']).decode('ascii'),
                             '978b90ace99c764841d2dd17d278fac4149962a3')

            pefile = SignedPEFile(f)

            # This should not raise any errors.
            signed_datas = list(pefile.signed_datas)
            # There may be multiple of these, if the windows binary was signed multiple
            # times, e.g. by different entities. Each of them adds a complete SignedData
            # blob to the binary. For our sample, there is only one blob.
            self.assertEqual(len(signed_datas), 1)
            signed_data = signed_datas[0]

            self.assertEqual(signed_data._rest_data, b'\0')

            signed_data.verify()

            # should work as well
            pefile.verify()

    def test_pciide(self):
        with open(str(root_dir / "test_data" / "pciide.sys"), "rb") as f:
            pefile = SignedPEFile(f)
            signed_datas = list(pefile.signed_datas)
            self.assertEqual(len(signed_datas), 1)
            signed_data = signed_datas[0]
            signed_data.verify()
            pefile.verify()

    def test_modified_pciide_fails(self):
        with open(str(root_dir / "test_data" / "pciide.sys"), "rb") as f:
            data = bytearray(f.read())
        data[1024] = 3
        bt = io.BytesIO(data)
        pefile = SignedPEFile(bt)
        signed_datas = list(pefile.signed_datas)
        self.assertEqual(len(signed_datas), 1)
        self.assertRaises(AuthenticodeVerificationError, signed_datas[0].verify)
        self.assertRaises(AuthenticodeVerificationError, pefile.verify)

    def test_simple(self):
        with open(str(root_dir / "test_data" / "simple"), "rb") as f:
            pefile = SignedPEFile(f)
            self.assertRaises(SignedPEParseError, list, pefile.signed_datas)
            self.assertRaises(SignedPEParseError, pefile.verify)

    def test_2A6E(self):
        with open(str(root_dir / "test_data" / "___2A6E.tmp"), "rb") as f:
            pefile = SignedPEFile(f)
            self.assertRaises(VerificationError, pefile.verify)


class CertificateTestCase(unittest.TestCase):
    def test_all_trusted_certificates_are_trusted(self):
        context = VerificationContext(trusted_certificate_store)
        for certificate in trusted_certificate_store:
            # Trust depends on the timestamp
            context.timestamp = certificate.valid_to
            chain = certificate.verify(context)
            self.assertListEqual(chain, [certificate])

    def test_trust_fails(self):
        # we get a certificate we currently trust
        for certificate in trusted_certificate_store:
            # we add it to an untrusted store
            store = CertificateStore(trusted=False)
            store.append(certificate)
            # and verify using this store
            context = VerificationContext(store, timestamp=certificate.valid_to)
            self.assertRaises(VerificationError, certificate.verify, context)

