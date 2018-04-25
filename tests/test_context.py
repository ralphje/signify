
import unittest

from signify.authenticode import TRUSTED_CERTIFICATE_STORE


class TrustedStoreTestCase(unittest.TestCase):
    def test_amount_of_certificates(self):
        self.assertEqual(len(TRUSTED_CERTIFICATE_STORE), 13)
