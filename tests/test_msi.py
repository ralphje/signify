import hashlib
import pathlib
import unittest

from olefile import OleFileIO

from signify.authenticode import AuthenticodeVerificationResult, SignedMsiFile
from signify.exceptions import AuthenticodeNotSignedError

root_dir = pathlib.Path(__file__).parent


class SignedMsiTestCase(unittest.TestCase):
    def test_prehash_for_root_entry_msi(self):
        expected_prehash = (
            "ba597a30a72f996caab7a031e1de97371b72bbef64bf05306a17eff94b181eeb"
        )

        with open(str(root_dir / "test_data" / "cmake.msi"), "rb") as f:
            m = hashlib.sha256()
            from olefile import OleFileIO

            with OleFileIO(f) as ole:
                SignedMsiFile._prehash_entry(ole.root, m)
        self.assertEqual(m.hexdigest(), expected_prehash)

    def test_prehash_for_stream_entry_msi(self):
        expected_prehash = (
            "01e22c4972a4a860356cc2f853df72354da4da291f4ad40384219dce703aab4f"
        )
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
        expected_prehash = (
            "24a86991966c64f2b31080bf2ef9313b2a2cc48b5523c374b3b73cedcc38d8ed"
        )
        with open(str(root_dir / "test_data" / "cmake.msi"), "rb") as f:
            msi_file = SignedMsiFile(f)
            prehash = msi_file._calculate_prehash(digest_algorithm=hashlib.sha256)

        self.assertEqual(prehash.hex(), expected_prehash)

    def test_cmake_msi_signed_data(self):
        with open(str(root_dir / "test_data" / "cmake.msi"), "rb") as f:
            expected_msi_hash = (
                "1ad3da8d96bdbc701ab4e237057da15302051775c982dc5c7c83e43b8d2a0ab2"
            )

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
        self.assertEqual(
            digicert_root.subject.dn,
            "CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert Inc, C=US",
        )
        self.assertEqual(
            digicert_intermediate.subject.dn,
            "CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O=DigiCert\, Inc., C=US",
        )
        self.assertEqual(
            kitware.subject.dn,
            "CN=Kitware\, Inc., O=Kitware\, Inc., L=Clifton Park, ST=New York, C=US, 2.5.4.5=2235734, 2.5.4.15=Private Organization, 1.3.6.1.4.1.311.60.2.1.2=New York, 1.3.6.1.4.1.311.60.2.1.3=US",
        )

    def test_putty_msi(self):
        """Putty msi does not have an extended digital signature."""
        with open(str(root_dir / "test_data" / "putty.msi"), "rb") as f:
            msi_file = SignedMsiFile(f)
            result = msi_file.verify()
        self.assertEqual(len(result), 1)
        _signed_data, certificate_chains = result[0]
        sectigo_root, sectigo_intermediate, tatham = certificate_chains[0]
        self.assertEqual(
            sectigo_root.subject.dn,
            "CN=Sectigo Public Code Signing Root R46, O=Sectigo Limited, C=GB",
        )
        self.assertEqual(
            sectigo_intermediate.subject.dn,
            "CN=Sectigo Public Code Signing CA R36, O=Sectigo Limited, C=GB",
        )
        self.assertEqual(
            tatham.subject.dn,
            "CN=Simon Tatham, O=Simon Tatham, ST=Cambridgeshire, C=GB",
        )

    def test_exe_file(self):
        with open(str(root_dir / "test_data" / "sigcheck.exe"), "rb") as f:
            msi_file = SignedMsiFile(f)
            with self.assertRaises(AuthenticodeNotSignedError):
                msi_file.verify()

    def test_msi_not_signed(self):
        with open(str(root_dir / "test_data" / "cmake_not_signed.msi"), "rb") as f:
            msi_file = SignedMsiFile(f)
            with self.assertRaises(AuthenticodeNotSignedError):
                msi_file.verify()
    
    def test_explain_verify_on_msi_not_signed(self):
        with open(str(root_dir / "test_data" / "cmake_not_signed.msi"), "rb") as f:
            msi_file = SignedMsiFile(f)
            self.assertTupleEqual(msi_file.explain_verify(), (AuthenticodeVerificationResult.NOT_SIGNED, AuthenticodeNotSignedError("missing DigitalSignature")))