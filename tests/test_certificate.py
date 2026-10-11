import itertools

import pytest

from signify.authenticode import (
    TRUSTED_CERTIFICATE_STORE,
    TRUSTED_CERTIFICATE_STORE_NO_CTL,
)
from signify.exceptions import VerificationError
from signify.x509 import Certificate
from signify.x509.context import CertificateStore, VerificationContext
from tests._utils import open_test_data


def has_known_signature_algorithm(certificate: Certificate) -> bool:
    # certvalidator cannot verify signature algorithms unknown to asn1crypto
    try:
        return certificate.asn1["signature_algorithm"].signature_algo is not None
    except ValueError:
        return False


def test_all_trusted_certificates_are_trusted():
    context = VerificationContext(TRUSTED_CERTIFICATE_STORE_NO_CTL)
    # only select 50 to speed up testing
    for certificate in itertools.islice(TRUSTED_CERTIFICATE_STORE_NO_CTL, 50):
        if not has_known_signature_algorithm(certificate):
            continue
        # Trust depends on the timestamp
        context.timestamp = certificate.valid_to
        chain = certificate.verify(context)
        assert chain == [certificate]


def test_no_duplicates_in_default_store():
    assert len(TRUSTED_CERTIFICATE_STORE) == len(set(TRUSTED_CERTIFICATE_STORE))


def test_certificate_with_unknown_public_key_algorithm():
    # ML-DSA root from the Microsoft trust store; asn1crypto cannot parse its key
    with open_test_data("certs/digicert_pqc_mldsa87_root.pem") as f:
        certificate = Certificate.from_pem(f.read())
    same_certificate = Certificate.from_der(certificate.asn1.dump())
    other_certificate = next(iter(TRUSTED_CERTIFICATE_STORE_NO_CTL))

    assert len({certificate, same_certificate}) == 1
    assert certificate == same_certificate
    assert certificate != other_certificate
    assert certificate in CertificateStore([certificate], trusted=True)


def test_trust_fails():
    # we get a certificate we currently trust
    for certificate in TRUSTED_CERTIFICATE_STORE_NO_CTL:
        # we add it to an untrusted store
        store = CertificateStore(trusted=False)
        store.append(certificate)
        # and verify using this store
        context = VerificationContext(store, timestamp=certificate.valid_to)
        with pytest.raises(VerificationError):
            certificate.verify(context)


def test_to_string():
    certificate = TRUSTED_CERTIFICATE_STORE.find_certificate(
        sha256_fingerprint=(
            "DF545BF919A2439C36983B54CDFC903DFA4F37D3996D8D84B4C31EEC6F3C163E"
        )
    )

    assert (
        certificate.issuer.dn
        == "CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, "
        "L=Redmond, ST=Washington, C=US",
    )


def test_to_string_with_commas():
    certificate = TRUSTED_CERTIFICATE_STORE.find_certificate(
        sha256_fingerprint=(
            "5B789987F3C4055B8700941B33783A5F16E0CFF937EA32011FE04779F7635308"
        )
    )

    assert (
        certificate.issuer.dn
        == r"OU=NO LIABILITY ACCEPTED\, (c)97 VeriSign\, Inc., OU=VeriSign Time"
        r" Stamping Service Root, "
        r"OU=VeriSign\, Inc., O=VeriSign Trust Network",
    )


def test_get_components():
    certificate = TRUSTED_CERTIFICATE_STORE.find_certificate(
        sha256_fingerprint=(
            "5B789987F3C4055B8700941B33783A5F16E0CFF937EA32011FE04779F7635308"
        )
    )

    result = list(certificate.issuer.get_components("OU"))
    assert (
        result
        == [
            "NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc.",
            "VeriSign Time Stamping Service Root",
            "VeriSign, Inc.",
        ],
    )
    assert list(certificate.issuer.get_components("CN")) == []


def test_get_components_none():
    certificate = TRUSTED_CERTIFICATE_STORE.find_certificate(
        sha256_fingerprint=(
            "5B789987F3C4055B8700941B33783A5F16E0CFF937EA32011FE04779F7635308"
        )
    )

    result = certificate.issuer.rdns
    assert (
        result
        == (
            ("OU", "NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc."),
            ("OU", "VeriSign Time Stamping Service Root"),
            ("OU", "VeriSign, Inc."),
            ("O", "VeriSign Trust Network"),
        ),
    )
