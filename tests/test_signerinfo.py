import hashlib
import unittest

import pytest
from asn1crypto.algos import DigestAlgorithm
from asn1crypto.core import Boolean

from signify.exceptions import ParseError
from signify.pkcs7.signer_info import _get_digest_algorithm


def test_acceptable_oid():
    sha1 = DigestAlgorithm()
    sha1["algorithm"] = "1.3.14.3.2.26"
    assert _get_digest_algorithm(sha1, location="test") == hashlib.sha1


@pytest.mark.parametrize("algorithm", ["1.2", "1.2.840.113549.1.9.3"])
def test_unknown_or_invalid_oid(algorithm):
    invalid = DigestAlgorithm()
    invalid["algorithm"] = algorithm
    with pytest.raises(ParseError):
        _get_digest_algorithm(invalid, location="test")


def test_unacceptable_oid():
    sha1 = DigestAlgorithm()
    sha1["algorithm"] = "1.3.14.3.2.26"
    with pytest.raises(ParseError):
        _get_digest_algorithm(sha1, location="test", acceptable=["md5"])


def test_null_parameters():
    sha1 = DigestAlgorithm()
    sha1["algorithm"] = "1.3.14.3.2.26"
    sha1["parameters"] = "\x05\0"  # null value
    assert _get_digest_algorithm(sha1, location="test") == hashlib.sha1


def test_non_null_parameters():
    with pytest.raises(TypeError):
        sha1 = DigestAlgorithm()
        sha1["algorithm"] = "1.3.14.3.2.26"
        sha1["parameters"] = Boolean(True)
        _get_digest_algorithm(sha1, location="test")
