import contextlib
import datetime
import io

import pytest

from signify.authenticode import TRUSTED_CERTIFICATE_STORE
from signify.authenticode.signed_file.pe import SignedPEFile
from signify.exceptions import (
    AuthenticodeNotSignedError,
    AuthenticodeVerificationError,
    SignedPEParseError,
    VerificationError,
)
from signify.x509 import Certificate
from signify.x509.context import CertificateStore
from tests._utils import open_test_data


@pytest.mark.parametrize(
    "filename",
    [
        "SoftwareUpdate.exe",
        "pciide.sys",
        "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198",
        # Test for SHA256 hashes used in sig
        "software_reporter_tool.exe",
        # uses a different contenttype, 1.2.840.113549.1.9.16.1.4 instead of Data
        "3a7de393a36ca8911cd0842a9a25b058",
        # Solarwinds includes a 1.3.6.1.4.1.311.3.3.1 type countersignature
        "SolarWinds.exe",
        # whois includes a 1.3.6.1.4.1.311.3.3.1 type countersignature
        "whois.exe",
        # Test for SHA256 hashes used in sig
        "software_reporter_tool.exe",
        # this tests a sample that has a v3 SignedData structure
        "7dc674b46d51cb42963417a487ef8e88e547e3e0902a1e236ff13c3f1fdd60e4.exe",
        # this tests a sample that has a v0 SignerInfo structure
        "spotify_sample.exe",
        # this tests a RFC3161 sample that has distinct hash and digest algorithms
        "zonealarm.exe",
        # this tests a sample that has an abnormal attribute order
        "8757bf55-0077-4df5-9807-122a3261ee40",
        # sample that is signed with a catalog as well
        "DXCore.dll",
        # this tests a sample that has two signed datas, that are both valid
        "sigcheck.exe",
    ],
)
def test_valid_signature(filename):
    with open_test_data(filename) as f:
        pefile = SignedPEFile(f)
        pefile.verify()


@pytest.mark.parametrize(
    "filename",
    [
        "___2A6E.tmp",
        # This tests against CVE-2020-0601
        "7z1900-x64_signed.exe",
        # This sample is expired
        "19e818d0da361c4feedd456fca63d68d4b024fbbd3d9265f606076c7ee72e8f8.ViR",
        # This sample is expired and revoked
        "jameslth",
    ],
)
def test_invalid_signature(filename):
    with open_test_data(filename) as f:
        pefile = SignedPEFile(f)
        with pytest.raises(VerificationError):
            pefile.verify()


def test_pciide():
    with open_test_data("pciide.sys") as f:
        pefile = SignedPEFile(f)
        signed_datas = list(pefile.embedded_signatures)
        assert len(signed_datas) == 1
        signed_data = signed_datas[0]
        signed_data.verify()
        pefile.verify()


def test_modified_pciide_fails():
    with open_test_data("pciide.sys") as f:
        data = bytearray(f.read())
    data[1024] = 3
    bt = io.BytesIO(data)
    pefile = SignedPEFile(bt)
    signed_datas = list(pefile.embedded_signatures)
    assert len(signed_datas) == 1
    with pytest.raises(AuthenticodeVerificationError):
        signed_datas[0].verify()
    with pytest.raises(AuthenticodeVerificationError):
        pefile.verify()


def test_simple():
    with open_test_data("simple") as f:
        pefile = SignedPEFile(f)
        with pytest.raises(AuthenticodeNotSignedError):
            pefile.verify()
        with pytest.raises(SignedPEParseError):
            list(pefile.iter_embedded_signatures(ignore_parse_errors=False))


def test_provide_hash():
    with open_test_data(
        "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
    ) as f:
        pefile = SignedPEFile(f)
        with pytest.raises(VerificationError):
            pefile.verify(expected_hashes={"sha1": b"asdf"})


def test_19e8_valid_within_period():
    """test whether the timestamp can be set on expired samples"""
    with open_test_data(
        "19e818d0da361c4feedd456fca63d68d4b024fbbd3d9265f606076c7ee72e8f8.ViR"
    ) as f:
        pefile = SignedPEFile(f)
        pefile.verify(
            verification_context_kwargs={
                "timestamp": datetime.datetime(2013, 1, 1, tzinfo=datetime.timezone.utc)
            }
        )


def test_sw_reporter():
    """Test for SHA256 hashes used in sig"""
    with open_test_data("software_reporter_tool.exe") as f:
        pefile = SignedPEFile(f)
        signed_datas = list(pefile.embedded_signatures)
        assert len(signed_datas) == 1
        signed_data = signed_datas[0]
        signed_data.verify()
        pefile.verify()


def test_whois_valid_countersignature_rfc3161():
    """whois includes a 1.3.6.1.4.1.311.3.3.1 type countersignature"""
    with open_test_data("whois.exe") as f:
        pefile = SignedPEFile(f)
        pefile.verify()

        # test that the signing time is correct in this case
        assert (
            next(
                iter(pefile.embedded_signatures)
            ).signer_info.countersigner.signing_time
            == datetime.datetime(
                2019, 12, 11, 8, 40, 17, 750_000, tzinfo=datetime.timezone.utc
            ),
        )


def test_jameslth_valid_when_revocation_not_checked():
    """this certificate is revoked"""
    with open_test_data("jameslth") as f:
        pefile = SignedPEFile(f)
        pefile.verify(
            verification_context_kwargs={
                "timestamp": datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
            }
        )


def test_jameslth_revoked():
    """this certificate is revoked"""
    # TODO: this certificate is now expired, so it will not show up as valid anyway
    with open_test_data("jameslth") as f:
        pefile = SignedPEFile(f)
        with pytest.raises(VerificationError):
            pefile.verify(
                verification_context_kwargs={
                    "allow_fetching": True,
                    "revocation_mode": "hard-fail",
                }
            )


@pytest.mark.parametrize("mode", ["all", "best", "any", "first"])
def test_multiple_signatures_all_valid(mode):
    """this tests a sample that has two signed datas, that are both valid"""
    with open_test_data("sigcheck.exe") as f:
        pefile = SignedPEFile(f)
        assert len(list(pefile.embedded_signatures)) == 2
        pefile.verify(multi_verify_mode=mode)


@pytest.mark.parametrize(
    ("mode", "patch_location", "expected"),
    [
        # this tests a sample that has an invalid sha-1 hash, but valid sha-256 hash
        (
            "all",
            "dfbdc3905728da39d9f74d857ac1d228a0ac0218",
            pytest.raises(VerificationError),
        ),
        (
            "best",
            "dfbdc3905728da39d9f74d857ac1d228a0ac0218",
            contextlib.nullcontext(),
        ),
        (
            "any",
            "dfbdc3905728da39d9f74d857ac1d228a0ac0218",
            contextlib.nullcontext(),
        ),
        (
            "first",
            "dfbdc3905728da39d9f74d857ac1d228a0ac0218",
            pytest.raises(VerificationError),
        ),
        # this tests a sample that has an valid sha-1 hash, but invalid sha-256 hash
        (
            "all",
            "a74a343be2234235f57f21b794fdbd379f246a388f7b17bf21cd1d26ece699ef",
            pytest.raises(VerificationError),
        ),
        (
            "best",
            "a74a343be2234235f57f21b794fdbd379f246a388f7b17bf21cd1d26ece699ef",
            pytest.raises(VerificationError),
        ),
        (
            "any",
            "a74a343be2234235f57f21b794fdbd379f246a388f7b17bf21cd1d26ece699ef",
            contextlib.nullcontext(),
        ),
        (
            "first",
            "a74a343be2234235f57f21b794fdbd379f246a388f7b17bf21cd1d26ece699ef",
            contextlib.nullcontext(),
        ),
    ],
)
def test_multiple_signatures_one_invalid(mode, patch_location, expected):
    """this tests a sample that has both a valid and an invalid hash in a signature,
    by patching the hashes in the signatures (i.e. making those signatures invalid)
    """

    with open_test_data("sigcheck.exe") as f:
        data = bytearray(f.read())

    patch_location_offset = data.index(bytes.fromhex(patch_location))
    data[patch_location_offset : patch_location_offset + 1] = b"\x00"

    with io.BytesIO(data) as f:
        pefile = SignedPEFile(f)
        with expected:
            pefile.verify(multi_verify_mode=mode)


@pytest.mark.parametrize("mode", ["all", "best", "any", "first"])
def test_multiple_signatures_all_invalid(mode):
    """this tests a sample that has only invalid signautres"""

    with open_test_data("sigcheck.exe") as f:
        data = bytearray(f.read())

    for patch_location in (
        "dfbdc3905728da39d9f74d857ac1d228a0ac0218",
        "a74a343be2234235f57f21b794fdbd379f246a388f7b17bf21cd1d26ece699ef",
    ):
        patch_location_offset = data.index(bytes.fromhex(patch_location))
        data[patch_location_offset : patch_location_offset + 1] = b"\x00"

    with io.BytesIO(data) as f:
        pefile = SignedPEFile(f)
        # we can test for the fact that all signatures are invalid here as well,
        # because the normal CTL will disallow sha1
        with pytest.raises(VerificationError):
            pefile.verify(multi_verify_mode=mode)


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        # should verify on this date
        (
            datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
            contextlib.nullcontext(),
        ),
        # should not verify on this date
        (
            datetime.datetime(2060, 1, 1, tzinfo=datetime.timezone.utc),
            pytest.raises(VerificationError),
        ),
    ],
)
def test_lifetime_signing(timestamp, expected):
    """this tests a sample that has a valid countersignature and a lifetime signing
    flag. it is self-signed, so we need to load that one as well
    """
    with open_test_data("kdbazis.dll.crt") as crt:
        certificate_store = CertificateStore(
            list(TRUSTED_CERTIFICATE_STORE) + list(Certificate.from_pems(crt.read())),
            trusted=True,
        )

    with open_test_data("kdbazis.dll") as f:
        pefile = SignedPEFile(f)
        with expected:
            pefile.verify(
                trusted_certificate_store=certificate_store,
                verification_context_kwargs={"timestamp": timestamp},
            )


def test_pe_sample_with_catalog():
    with (
        open_test_data("DXCore.dll") as f,
        open_test_data(
            "115fe8649854ad531fb7ecd1318fbee6b33c9cbd78f02ed582092a96d5eb5899.cat"
        ) as cat,
    ):
        pefile = SignedPEFile(f)
        assert len(list(pefile.embedded_signatures)) == 1
        assert len(list(pefile.signatures)) == 1
        pefile.add_catalog(cat)
        assert len(list(pefile.signatures)) == 2
        pefile.verify(signature_types="embedded")
