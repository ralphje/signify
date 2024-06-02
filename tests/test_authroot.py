import pathlib
import unittest

from signify.authenticode.authroot import CertificateTrustList

root_dir = pathlib.Path(__file__).parent


class AuthrootTestCase(unittest.TestCase):
    def test_certificate_can_be_opened(self):
        ctl = CertificateTrustList.from_stl_file()
        # assume at least 400 items in the list
        self.assertGreaterEqual(len(ctl.subjects), 400)
