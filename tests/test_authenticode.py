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


import binascii
import datetime
import hashlib
import io
import itertools
import pathlib
import unittest

from olefile import OleFileIO

from signify.authenticode import (
    CERTIFICATE_LOCATION,
    TRUSTED_CERTIFICATE_STORE,
    TRUSTED_CERTIFICATE_STORE_NO_CTL,
)
from signify.authenticode.signed_msi import SignedMsiFile
from signify.authenticode.signed_pe import SignedPEFile
from signify.exceptions import (
    AuthenticodeNotSignedError,
    AuthenticodeVerificationError,
    SignedPEParseError,
    VerificationError,
)
from signify.fingerprinter import AuthenticodeFingerprinter
from signify.x509 import Certificate
from signify.x509.context import (
    CertificateStore,
    FileSystemCertificateStore,
    VerificationContext,
)

root_dir = pathlib.Path(__file__).parent
trusted_certificate_store = FileSystemCertificateStore(
    location=CERTIFICATE_LOCATION, trusted=True
)


class AuthenticodeParserTestCase(unittest.TestCase):
    def test_software_update(self):
        with open(str(root_dir / "test_data" / "SoftwareUpdate.exe"), "rb") as f:
            fingerprinter = AuthenticodeFingerprinter(f)
            fingerprinter.add_authenticode_hashers(hashlib.sha1)
            hashes = fingerprinter.hash()

            # Sanity check that the authenticode hash is still correct
            self.assertEqual(
                binascii.hexlify(hashes["sha1"]).decode("ascii"),
                "978b90ace99c764841d2dd17d278fac4149962a3",
            )

            pefile = SignedPEFile(f)

            # This should not raise any errors.
            signed_datas = list(pefile.signed_datas)
            # There may be multiple of these, if the windows binary was signed multiple
            # times, e.g. by different entities. Each of them adds a complete SignedData
            # blob to the binary. For our sample, there is only one blob.
            self.assertEqual(len(signed_datas), 1)
            signed_data = signed_datas[0]

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
            self.assertRaises(AuthenticodeNotSignedError, pefile.verify)
            self.assertRaises(
                SignedPEParseError,
                list,
                pefile.iter_signed_datas(ignore_parse_errors=False),
            )

    def test_2A6E(self):
        with open(str(root_dir / "test_data" / "___2A6E.tmp"), "rb") as f:
            pefile = SignedPEFile(f)
            self.assertRaises(VerificationError, pefile.verify)

    def test_0d8c_valid(self):
        with open(
            str(
                root_dir
                / "test_data"
                / "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
            ),
            "rb",
        ) as f:
            pefile = SignedPEFile(f)
            pefile.verify(trusted_certificate_store=TRUSTED_CERTIFICATE_STORE_NO_CTL)

    def test_provide_hash(self):
        with open(
            str(
                root_dir
                / "test_data"
                / "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
            ),
            "rb",
        ) as f:
            pefile = SignedPEFile(f)
            with self.assertRaises(VerificationError):
                pefile.verify(
                    trusted_certificate_store=TRUSTED_CERTIFICATE_STORE_NO_CTL,
                    expected_hashes={"sha1": b"asdf"},
                )

    def test_19e8_expired(self):
        """this is an expired sample"""
        with open(
            str(
                root_dir
                / "test_data"
                / "19e818d0da361c4feedd456fca63d68d4b024fbbd3d9265f606076c7ee72e8f8.ViR"
            ),
            "rb",
        ) as f:
            pefile = SignedPEFile(f)
            self.assertRaises(VerificationError, pefile.verify)

    def test_19e8_valid_within_period(self):
        """test whether the timestamp can be set on expired samples"""
        with open(
            str(
                root_dir
                / "test_data"
                / "19e818d0da361c4feedd456fca63d68d4b024fbbd3d9265f606076c7ee72e8f8.ViR"
            ),
            "rb",
        ) as f:
            pefile = SignedPEFile(f)
            pefile.verify(
                verification_context_kwargs={
                    "timestamp": datetime.datetime(
                        2013, 1, 1, tzinfo=datetime.timezone.utc
                    )
                }
            )

    def test_sw_reporter(self):
        """Test for SHA256 hashes used in sig"""
        with open(
            str(root_dir / "test_data" / "software_reporter_tool.exe"), "rb"
        ) as f:
            pefile = SignedPEFile(f)
            signed_datas = list(pefile.signed_datas)
            self.assertEqual(len(signed_datas), 1)
            signed_data = signed_datas[0]
            signed_data.verify()
            pefile.verify()

    def test_7z1900_invalid_cve2020_0601(self):
        """This tests against CVE-2020-0601"""
        with open(str(root_dir / "test_data" / "7z1900-x64_signed.exe"), "rb") as f:
            pefile = SignedPEFile(f)
            self.assertRaises(VerificationError, pefile.verify)

    def test_3a7de393a36ca8911cd0842a9a25b058_valid_different_contenttype(self):
        """uses a different contenttype, 1.2.840.113549.1.9.16.1.4 instead of Data"""
        with open(
            str(root_dir / "test_data" / "3a7de393a36ca8911cd0842a9a25b058"), "rb"
        ) as f:
            pefile = SignedPEFile(f)
            pefile.verify()

    def test_solwarwinds_valid_countersignature_rfc3161(self):
        """Solarwinds includes a 1.3.6.1.4.1.311.3.3.1 type countersignature"""
        with open(str(root_dir / "test_data" / "SolarWinds.exe"), "rb") as f:
            pefile = SignedPEFile(f)
            pefile.verify()

    def test_whois_valid_countersignature_rfc3161(self):
        """whois includes a 1.3.6.1.4.1.311.3.3.1 type countersignature"""
        with open(str(root_dir / "test_data" / "whois.exe"), "rb") as f:
            pefile = SignedPEFile(f)
            pefile.verify()

            # test that the signing time is correct in this case
            self.assertEqual(
                list(pefile.signed_datas)[0].signer_info.countersigner.signing_time,
                datetime.datetime(
                    2019, 12, 11, 8, 40, 17, 750_000, tzinfo=datetime.timezone.utc
                ),
            )

    def test_jameslth_valid_when_revocation_not_checked(self):
        """this certificate is revoked"""
        with open(str(root_dir / "test_data" / "jameslth"), "rb") as f:
            pefile = SignedPEFile(f)
            pefile.verify(
                verification_context_kwargs={
                    "timestamp": datetime.datetime(
                        2021, 1, 1, tzinfo=datetime.timezone.utc
                    )
                }
            )

    def test_jameslth_revoked(self):
        """this certificate is revoked"""
        # TODO: this certificate is now expired, so it will not show up as valid anyway
        with open(str(root_dir / "test_data" / "jameslth"), "rb") as f:
            pefile = SignedPEFile(f)
            with self.assertRaises(VerificationError):
                pefile.verify(
                    verification_context_kwargs={
                        "allow_fetching": True,
                        "revocation_mode": "hard-fail",
                    }
                )

    def test_zonealarm_rfc3161_different_hash_and_digest_algorithms(self):
        """this tests a RFC3161 sample that has distinct hash and digest algorithms"""
        with open(str(root_dir / "test_data" / "zonealarm.exe"), "rb") as f:
            pefile = SignedPEFile(f)
            pefile.verify()

    def test_prehash_for_root_entry_msi(self):
        expected_prehash = "ba597a30a72f996caab7a031e1de97371b72bbef64bf05306a17eff94b181eeb"

        with open(str(root_dir / "test_data" / "cmake.msi"), "rb") as f:
            m = hashlib.sha256()
            from olefile import OleFileIO
            with OleFileIO(f) as ole:
                SignedMsiFile._prehash_entry(ole.root, m)
        self.assertEqual(m.hexdigest(), expected_prehash)
    
    def test_prehash_for_stream_entry_msi(self):
        expected_prehash = "01e22c4972a4a860356cc2f853df72354da4da291f4ad40384219dce703aab4f"
        with open(str(root_dir / "test_data" / "cmake.msi"), "rb") as f:
            m = hashlib.sha256()
            with OleFileIO(f) as ole:
                tested_entry = None
                for entry in ole.root.kids:
                    if entry.name == "\x05SummaryInformation":
                        tested_entry = entry
                        break
                SignedMsiFile._prehash_entry(tested_entry, m)
        self.assertEqual(m.hexdigest(), expected_prehash)
    
    def test_prehash_for_the_full_msi(self):
        expected_prehash = "24a86991966c64f2b31080bf2ef9313b2a2cc48b5523c374b3b73cedcc38d8ed"
        with open(str(root_dir / "test_data" / "cmake.msi"), "rb") as f:
            msi_file = SignedMsiFile(f)

        prehash = msi_file._calculate_prehash(digest_algorithm=hashlib.sha256)
            
        self.assertEqual(prehash.hex(), expected_prehash)

    def test_cmake_msi_signed_data(self):
        with open(str(root_dir / "test_data" / "cmake.msi"), "rb") as f:
            expected_msi_hash = "1ad3da8d96bdbc701ab4e237057da15302051775c982dc5c7c83e43b8d2a0ab2"
            
            msi_file = SignedMsiFile(f)
            signed_datas = list(msi_file.signed_datas)
            self.assertEqual(len(signed_datas), 1)
            signed_data = signed_datas[0]

            self.assertEqual(signed_data.indirect_data.digest.hex(), expected_msi_hash)
            signed_data.verify(expected_hash=bytes.fromhex(expected_msi_hash))
    
    def test_cmake_msi(self):
        with open(str(root_dir / "test_data" / "cmake.msi"), "rb") as f:
            msi_file = SignedMsiFile(f)
            result = msi_file.verify()
        self.assertEqual(len(result), 1)
        _signed_data, certificate_chains = result[0]
        digicert_root, digicert_intermediate, kitware = certificate_chains[0]
        self.assertEqual(digicert_root.subject.dn, "CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert Inc, C=US")
        self.assertEqual(digicert_intermediate.subject.dn, "CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O=DigiCert\, Inc., C=US")
        self.assertEqual(kitware.subject.dn, "CN=Kitware\, Inc., O=Kitware\, Inc., L=Clifton Park, ST=New York, C=US, 2.5.4.5=2235734, 2.5.4.15=Private Organization, 1.3.6.1.4.1.311.60.2.1.2=New York, 1.3.6.1.4.1.311.60.2.1.3=US")

    def test_abnormal_attribute_order(self):
        """this tests a sample that has an abnormal attribute order"""
        with open(
            str(root_dir / "test_data" / "8757bf55-0077-4df5-9807-122a3261ee40"), "rb"
        ) as f:
            pefile = SignedPEFile(f)
            pefile.verify()

    def test_multiple_signatures_all_valid(self):
        """this tests a sample that has two signed datas, that are both valid"""
        with open(str(root_dir / "test_data" / "sigcheck.exe"), "rb") as f:
            pefile = SignedPEFile(f)
            self.assertEqual(len(list(pefile.signed_datas)), 2)

            for mode in ("all", "first", "any", "best"):
                with self.subTest(multi_verify_mode=mode):
                    pefile.verify(
                        trusted_certificate_store=TRUSTED_CERTIFICATE_STORE_NO_CTL,
                        multi_verify_mode=mode,
                    )

    def test_multiple_signatures_invalid_sha1(self):
        """this tests a sample that has an invalid sha-1 hash, but valid sha-256 hash"""
        with open(str(root_dir / "test_data" / "sigcheck_sha1_patched.exe"), "rb") as f:
            pefile = SignedPEFile(f)
            for mode in ("all", "first"):
                with (
                    self.subTest(multi_verify_mode=mode),
                    self.assertRaises(VerificationError),
                ):
                    pefile.verify(
                        trusted_certificate_store=TRUSTED_CERTIFICATE_STORE_NO_CTL,
                        multi_verify_mode=mode,
                    )
            for mode in ("any", "best"):
                with self.subTest(multi_verify_mode=mode):
                    pefile.verify(
                        trusted_certificate_store=TRUSTED_CERTIFICATE_STORE_NO_CTL,
                        multi_verify_mode=mode,
                    )

    def test_multiple_signatures_invalid_sha256(self):
        """this tests a sample that has an valid sha-1 hash, but invalid sha-256 hash"""
        with open(
            str(root_dir / "test_data" / "sigcheck_sha256_patched.exe"), "rb"
        ) as f:
            pefile = SignedPEFile(f)
            for mode in ("all", "best"):
                with (
                    self.subTest(multi_verify_mode=mode),
                    self.assertRaises(VerificationError),
                ):
                    pefile.verify(
                        trusted_certificate_store=TRUSTED_CERTIFICATE_STORE_NO_CTL,
                        multi_verify_mode=mode,
                    )
            for mode in ("first", "any"):
                with self.subTest(multi_verify_mode=mode):
                    pefile.verify(
                        trusted_certificate_store=TRUSTED_CERTIFICATE_STORE_NO_CTL,
                        multi_verify_mode=mode,
                    )

    def test_multiple_signatures_all_invalid(self):
        """this tests a sample that has only invalid signautres"""
        with open(
            str(root_dir / "test_data" / "sigcheck_sha256_patched.exe"), "rb"
        ) as f:
            pefile = SignedPEFile(f)
            # we can test for the fact that all signatures are invalid here as well,
            # because the normal CTL will disallow sha1
            for mode in ("all", "best", "first", "any"):
                with (
                    self.subTest(multi_verify_mode=mode),
                    self.assertRaises(VerificationError),
                ):
                    pefile.verify(multi_verify_mode=mode)

    def test_signeddata_v3(self):
        """this tests a sample that has a v3 SignedData structure"""
        with open(
            str(
                root_dir
                / "test_data"
                / "7dc674b46d51cb42963417a487ef8e88e547e3e0902a1e236ff13c3f1fdd60e4.exe"
            ),
            "rb",
        ) as f:
            pefile = SignedPEFile(f)
            pefile.verify()

    def test_signerinfo_v0(self):
        """this tests a sample that has a v0 SignerInfo structure"""
        with open(
            str(root_dir / "test_data" / "spotify_sample.exe"),
            "rb",
        ) as f:
            pefile = SignedPEFile(f)
            pefile.verify()

    def test_lifetime_signing(self):
        """this tests a sample that has a valid countersignature and a lifetime signing
        flag. it is self-signed, so we need to load that one as well
        """
        certificate_store = CertificateStore(
            list(TRUSTED_CERTIFICATE_STORE_NO_CTL)
            + list(
                Certificate.from_pems(
                    (root_dir / "test_data" / "kdbazis.dll.crt").read_bytes()
                )
            ),
            trusted=True,
        )

        with open(
            str(root_dir / "test_data" / "kdbazis.dll"),
            "rb",
        ) as f:
            pefile = SignedPEFile(f)
            # should verify on this date
            pefile.verify(
                trusted_certificate_store=certificate_store,
                verification_context_kwargs={
                    "timestamp": datetime.datetime(
                        2024, 1, 1, tzinfo=datetime.timezone.utc
                    )
                },
            )
            # should not verify on this date
            with self.assertRaises(VerificationError):
                pefile.verify(
                    trusted_certificate_store=certificate_store,
                    verification_context_kwargs={
                        "timestamp": datetime.datetime(
                            2060, 1, 1, tzinfo=datetime.timezone.utc
                        )
                    },
                )


class CertificateTestCase(unittest.TestCase):
    def test_all_trusted_certificates_are_trusted(self):
        context = VerificationContext(trusted_certificate_store)
        # only select 50 to speed up testing
        for certificate in itertools.islice(trusted_certificate_store, 50):
            # Trust depends on the timestamp
            context.timestamp = certificate.valid_to
            chain = certificate.verify(context)
            self.assertListEqual(chain, [certificate])

    def test_no_duplicates_in_default_store(self):
        self.assertEqual(
            len(TRUSTED_CERTIFICATE_STORE), len(set(TRUSTED_CERTIFICATE_STORE))
        )

    def test_trust_fails(self):
        # we get a certificate we currently trust
        for certificate in trusted_certificate_store:
            # we add it to an untrusted store
            store = CertificateStore(trusted=False)
            store.append(certificate)
            # and verify using this store
            context = VerificationContext(store, timestamp=certificate.valid_to)
            self.assertRaises(VerificationError, certificate.verify, context)
