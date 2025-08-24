import datetime

import pytest

from signify.authenticode import (
    TRUSTED_CERTIFICATE_STORE,
    TRUSTED_CERTIFICATE_STORE_NO_CTL,
)
from signify.authenticode.signed_file.pe import SignedPEFile
from signify.exceptions import VerificationError
from signify.x509 import CertificateStore
from signify.x509.certificates import Certificate
from signify.x509.context import VerificationContext
from tests._utils import open_test_data


def test_amount_of_certificates():
    assert len(TRUSTED_CERTIFICATE_STORE) >= 40


def test_potential_chains():
    with open_test_data(
        "19e818d0da361c4feedd456fca63d68d4b024fbbd3d9265f606076c7ee72e8f8.ViR"
    ) as f:
        pefile = SignedPEFile(f)
        for signed_data in pefile.embedded_signatures:
            context = VerificationContext(
                TRUSTED_CERTIFICATE_STORE_NO_CTL, signed_data.certificates
            )
            potential_chains = list(signed_data.signer_info.potential_chains(context))
            assert len(potential_chains) == 2
            # for chain in potential_chains:
            #    print("xxxx")
            #    for cert in chain:
            #        print(cert)


@pytest.mark.skipif(
    datetime.datetime.now() > datetime.datetime(2025, 9, 25),
    reason="revoked certificate expired",
)
def test_revoked_certificate():
    with open_test_data("certs/revoked.badssl.com.pem") as f:
        certs = list(Certificate.from_pems(f.read()))
        cert = certs[0]
        intermediate = CertificateStore(certs[1:])

    # check that when we do not verify the CRL it does not fail
    context = VerificationContext(TRUSTED_CERTIFICATE_STORE_NO_CTL, intermediate)
    context.verify(cert)

    context = VerificationContext(
        TRUSTED_CERTIFICATE_STORE_NO_CTL,
        intermediate,
        allow_fetching=True,
        revocation_mode="hard-fail",
    )
    with pytest.raises(VerificationError):
        context.verify(cert)


def test_fingerprint_with_financial_criteria():
    with open_test_data("certs/codetwo.pem") as f:
        cert = Certificate.from_pem(f.read())

    assert cert.sha1_fingerprint == "a71f6477a8ad571d2abeee4e20acdc37f96678e0"
    assert (
        cert.extensions["microsoft_spc_financial_criteria"]
        == {"financial_info_available": False, "meets_criteria": True},
    )
