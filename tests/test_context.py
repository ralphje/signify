import pathlib
import unittest

from signify.authenticode import TRUSTED_CERTIFICATE_STORE
from signify.context import VerificationContext
from signify.signed_pe import SignedPEFile

root_dir = pathlib.Path(__file__).parent


class TrustedStoreTestCase(unittest.TestCase):
    def test_amount_of_certificates(self):
        self.assertEqual(len(TRUSTED_CERTIFICATE_STORE), 13)


class ContextTestCase(unittest.TestCase):
    def test_potential_chains(self):
        with open(str(root_dir / "test_data" / "19e818d0da361c4feedd456fca63d68d4b024fbbd3d9265f606076c7ee72e8f8.ViR"), "rb") as f:
            pefile = SignedPEFile(f)
            for signed_data in pefile.signed_datas:
                context = VerificationContext(TRUSTED_CERTIFICATE_STORE, signed_data.certificates)
                potential_chains = list(signed_data.signer_info.potential_chains(context))
                self.assertEqual(len(potential_chains), 3)  # TODO: should be two, since there is one duplicate
                # for chain in potential_chains:
                #    print("xxxx")
                #    for cert in chain:
                #        print(cert)




