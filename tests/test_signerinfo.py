import hashlib
import unittest

from asn1crypto.algos import DigestAlgorithm
from asn1crypto.core import Boolean

from signify.exceptions import ParseError
from signify.pkcs7.signerinfo import _get_digest_algorithm


class GetDigestAlgorithmTest(unittest.TestCase):
    def test_acceptable_oid(self):
        sha1 = DigestAlgorithm()
        sha1["algorithm"] = "1.3.14.3.2.26"
        self.assertEqual(_get_digest_algorithm(sha1, location="test"), hashlib.sha1)

    def test_unknown_oid(self):
        invalid = DigestAlgorithm()
        invalid["algorithm"] = "1.2"
        self.assertRaises(ParseError, _get_digest_algorithm, invalid, location="test")

    def test_non_hashlib_oid(self):
        invalid = DigestAlgorithm()
        invalid["algorithm"] = "1.2.840.113549.1.9.3"
        self.assertRaises(ParseError, _get_digest_algorithm, invalid, location="test")

    def test_unacceptable_oid(self):
        sha1 = DigestAlgorithm()
        sha1["algorithm"] = "1.3.14.3.2.26"
        self.assertRaises(
            ParseError,
            _get_digest_algorithm,
            sha1,
            location="test",
            acceptable=["md5"],
        )

    def test_null_parameters(self):
        sha1 = DigestAlgorithm()
        sha1["algorithm"] = "1.3.14.3.2.26"
        sha1["parameters"] = "\x05\0"  # null value
        self.assertEqual(_get_digest_algorithm(sha1, location="test"), hashlib.sha1)

    def test_non_null_parameters(self):
        with self.assertRaises(TypeError):
            sha1 = DigestAlgorithm()
            sha1["algorithm"] = "1.3.14.3.2.26"
            sha1["parameters"] = Boolean(True)
            _get_digest_algorithm(sha1, location="test")
