import hashlib

from signify.authenticode import AuthenticodeVerificationResult
from signify.authenticode.indirect_data import IndirectData
from signify.authenticode.trust_list import CertificateTrustList
from tests._utils import open_test_data


def test_open_authroot():
    ctl = CertificateTrustList.from_stl_file()
    # assume at least 400 items in the list
    assert len(list(ctl.subjects)) >= 400
    assert ctl.subject_usage == ["microsoft_root_list_signer"]
    assert ctl.explain_verify() == (AuthenticodeVerificationResult.OK, None)


def test_open_catalog_sha1():
    with open_test_data("oem89.cat") as f:
        ctl = CertificateTrustList.from_envelope(f.read())

    assert len(list(ctl.subjects)) == 1
    assert ctl.subject_algorithm == hashlib.sha1
    assert ctl.subject_usage == ["microsoft_catalog_list"]

    subject = next(iter(ctl.subjects))
    assert isinstance(subject.indirect_data, IndirectData)
    assert subject.identifier_str == "B1E795B69B4C2A901A8BC8E8B36E988C6C05D836"
    assert (
        subject.indirect_data.digest.hex() == "b1e795b69b4c2a901a8bc8e8b36e988c6c05d836"
    )
    assert subject.catalog_namevalue is not None
    assert subject.catalog_memberinfo is not None


def test_open_catalog_sha256():
    with open_test_data(
        "115fe8649854ad531fb7ecd1318fbee6b33c9cbd78f02ed582092a96d5eb5899.cat"
    ) as f:
        ctl = CertificateTrustList.from_envelope(f.read())

    assert len(list(ctl.subjects)) == 20
    assert ctl.subject_algorithm == hashlib.sha256
    assert ctl.subject_usage == ["microsoft_catalog_list"]

    subject = next(iter(ctl.subjects))
    assert isinstance(subject.indirect_data, IndirectData)
    assert (
        subject.identifier_str
        == "06fa542ca0a1626e11e99e79896c9eaa79b5cfc3f9ad0ac8b84d4b2e8c5a292c"
    )
    assert (
        subject.indirect_data.digest.hex()
        == "06fa542ca0a1626e11e99e79896c9eaa79b5cfc3f9ad0ac8b84d4b2e8c5a292c"
    )
    assert subject.catalog_memberinfo is None
