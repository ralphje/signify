import datetime
import pathlib
import unittest

from signify.authenticode import (
    TRUSTED_CERTIFICATE_STORE,
    TRUSTED_CERTIFICATE_STORE_NO_CTL,
)
from signify.authenticode.signed_pe import SignedPEFile
from signify.exceptions import VerificationError
from signify.x509.certificates import Certificate
from signify.x509.context import FileSystemCertificateStore, VerificationContext

root_dir = pathlib.Path(__file__).parent


class TrustedStoreTestCase(unittest.TestCase):
    def test_amount_of_certificates(self):
        self.assertGreaterEqual(len(TRUSTED_CERTIFICATE_STORE), 40)


class ContextTestCase(unittest.TestCase):
    def test_potential_chains(self):
        with open(
            str(
                root_dir
                / "test_data"
                / "19e818d0da361c4feedd456fca63d68d4b024fbbd3d9265f606076c7ee72e8f8.ViR"
            ),
            "rb",
        ) as f:
            pefile = SignedPEFile(f)
            for signed_data in pefile.signed_datas:
                context = VerificationContext(
                    TRUSTED_CERTIFICATE_STORE_NO_CTL, signed_data.certificates
                )
                potential_chains = list(
                    signed_data.signer_info.potential_chains(context)
                )
                self.assertEqual(len(potential_chains), 2)
                # for chain in potential_chains:
                #    print("xxxx")
                #    for cert in chain:
                #        print(cert)


class ValidationTestCase(unittest.TestCase):
    @unittest.skipIf(
        datetime.datetime.now() > datetime.datetime(2022, 10, 27),
        "revoked certificate expired",
    )
    def test_revoked_certificate(self):
        root = FileSystemCertificateStore(
            root_dir / "certs" / "digicert-global-root-ca.pem", trusted=True
        )
        intermediate = FileSystemCertificateStore(
            root_dir / "certs" / "rapidssl-tls-2020.pem"
        )
        with open(str(root_dir / "certs" / "revoked.badssl.com.pem"), "rb") as f:
            cert = Certificate.from_pem(f.read())

        # check that when we do not verify the CRL it does not fail
        context = VerificationContext(root, intermediate)
        context.verify(cert)

        context = VerificationContext(
            root, intermediate, allow_fetching=True, revocation_mode="hard-fail"
        )
        with self.assertRaises(VerificationError):
            context.verify(cert)
