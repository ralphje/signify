import hashlib

import pytest

from signify.authenticode import AuthenticodeVerificationResult
from signify.exceptions import AuthenticodeNotSignedError, SignedMsiParseError
from tests._utils import open_test_data

olefile = pytest.importorskip("olefile")

from signify.authenticode.signed_file import SignedMsiFile


def test_prehash_for_root_entry_msi():
    with open_test_data("cmake.msi") as f:
        m = hashlib.sha256()
        with olefile.OleFileIO(f) as ole:
            SignedMsiFile._prehash_entry(ole.root, m)
    assert (
        m.hexdigest()
        == "ba597a30a72f996caab7a031e1de97371b72bbef64bf05306a17eff94b181eeb"
    )


def test_prehash_for_stream_entry_msi():
    with open_test_data("cmake.msi") as f:
        m = hashlib.sha256()
        with olefile.OleFileIO(f) as ole:
            tested_entry = None
            for entry in ole.root.kids:
                if entry.name == "\x05SummaryInformation":
                    tested_entry = entry
                    break
            SignedMsiFile._prehash_entry(tested_entry, m)
    assert (
        m.hexdigest()
        == "01e22c4972a4a860356cc2f853df72354da4da291f4ad40384219dce703aab4f"
    )


def test_prehash_for_the_full_msi():
    with open_test_data("cmake.msi") as f:
        msi_file = SignedMsiFile(f)
        prehash = msi_file._calculate_prehash(digest_algorithm=hashlib.sha256)

    assert (
        prehash.hex()
        == "24a86991966c64f2b31080bf2ef9313b2a2cc48b5523c374b3b73cedcc38d8ed"
    )


def test_cmake_msi_signed_data():
    with open_test_data("cmake.msi") as f:
        msi_file = SignedMsiFile(f)
        signed_datas = list(msi_file.embedded_signatures)
        assert len(signed_datas) == 1
        signed_data = signed_datas[0]

        expected_msi_hash = (
            "1ad3da8d96bdbc701ab4e237057da15302051775c982dc5c7c83e43b8d2a0ab2"
        )
        assert signed_data.indirect_data.digest.hex() == expected_msi_hash
        signed_data.verify(expected_hash=bytes.fromhex(expected_msi_hash))


def test_cmake_msi():
    with open_test_data("cmake.msi") as f:
        msi_file = SignedMsiFile(f)
        result = msi_file.verify()
    assert len(result) == 1
    _signed_data, indirect_data, certificate_chains = result[0]
    digicert_root, digicert_intermediate, kitware = certificate_chains[0]
    assert (
        digicert_root.subject.dn
        == r"CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert Inc,"
        r" C=US",
    )
    assert (
        digicert_intermediate.subject.dn
        == r"CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1,"
        r" O=DigiCert\, Inc., C=US",
    )
    assert (
        kitware.subject.dn
        == r"CN=Kitware\, Inc., O=Kitware\, Inc., L=Clifton Park, ST=New York,"
        r" C=US, serialNumber=2235734, businessCategory=Private Organization,"
        r" jurisdictionOfIncorporationStateOrProvinceName=New York,"
        r" jurisdictionOfIncorporationCountryName=US",
    )


def test_putty_msi():
    """Putty msi does not have an extended digital signature."""
    with open_test_data("putty.msi") as f:
        msi_file = SignedMsiFile(f)
        result = msi_file.verify()
    assert len(result) == 1
    _, _, certificate_chains = result[0]
    sectigo_root, sectigo_intermediate, tatham = certificate_chains[0]
    assert (
        sectigo_root.subject.dn
        == "CN=Sectigo Public Code Signing Root R46, O=Sectigo Limited, C=GB",
    )
    assert (
        sectigo_intermediate.subject.dn
        == "CN=Sectigo Public Code Signing CA R36, O=Sectigo Limited, C=GB",
    )
    assert (
        tatham.subject.dn == "CN=Simon Tatham, O=Simon Tatham, ST=Cambridgeshire, C=GB",
    )


def test_exe_file():
    with open_test_data("sigcheck.exe") as f, pytest.raises(SignedMsiParseError):
        SignedMsiFile(f)


def test_msi_not_signed():
    with open_test_data("cmake_not_signed.msi") as f:
        msi_file = SignedMsiFile(f)
        with pytest.raises(AuthenticodeNotSignedError):
            msi_file.verify()
        assert msi_file.explain_verify() == (
            AuthenticodeVerificationResult.NOT_SIGNED,
            AuthenticodeNotSignedError(
                "The MSI file is missing a DigitalSignature stream."
            ),
        )
