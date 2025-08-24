import pathlib

from signify.authenticode import AuthenticodeVerificationResult
from signify.authenticode.trust_list import CertificateTrustList

root_dir = pathlib.Path(__file__).parent


def test_authroot_can_be_opened():
    ctl = CertificateTrustList.from_stl_file()
    # assume at least 400 items in the list
    assert len(ctl.subjects) >= 400


def test_ctl_is_verified():
    ctl = CertificateTrustList.from_stl_file()
    assert ctl.explain_verify() == (AuthenticodeVerificationResult.OK, None)
