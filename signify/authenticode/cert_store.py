import pathlib

import mscerts

from signify.authenticode.trust_list import CertificateTrustList
from signify.x509 import FileSystemCertificateStore

CERTIFICATE_LOCATION = pathlib.Path(mscerts.where(stl=False))
LEGACY_CERTIFICATES = {
    # Microsoft Root Authority
    "a43489159a520f0d93d032ccaf37e7fe20a8b419": None,  # all
    # Microsoft Root Certificate Authority
    "cdd4eeae6000ac7f40c3802c171e30148030c072": None,  # all
    # Microsoft Root Certificate Authority 2010
    "3b1efd3a66ea28b16697394703a72ca340a05bd5": None,  # all
    # Microsoft Root Certificate Authority 2011
    "8f43288ad272f3103b6fb1428485ea3014c0bcfe": None,  # all
    # Copyright (c) 1997 Microsoft Corp.
    "245c97df7514e7cf2df8be72ae957b9e04741e85": ["time_stamping"],
    # Microsoft Authenticode(tm) Root Authority
    "7f88cd7223f3c813818c994614a89c99fa3b5247": ["email_protection", "code_signing"],
    # NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc.
    "18f7c1fcc3090203fd5baa2f861a754976c8dd25": ["time_stamping"],
    # Thawte Timestamping CA
    "be36a4562fb2ee05dbb3d32323adf445084ed656": ["time_stamping"],
    # Symantec Enterprise Mobile Root for Microsoft
    "92b46c76e13054e104f230517e6e504d43ab10b5": ["code_signing"],
    # Microsoft ECC Product Root Certificate Authority 2018
    "06f1aa330b927b753a40e68cdf22e34bcbef3352": None,  # all
    # Microsoft ECC TS Root Certificate Authority 2018
    "31f9fc8ba3805986b721ea7295c65b3a44534274": None,  # all
    # Microsoft Time Stamp Root Certificate Authority 2014
    "0119e81be9a14cd8e22f40ac118c687ecba3f4d8": None,  # all
}
LEGACY_CERTIFICATES_LOCATION = pathlib.Path(__file__).parent / "legacy-certs.pem"
TRUSTED_CERTIFICATE_STORE_NO_CTL = FileSystemCertificateStore(
    location=CERTIFICATE_LOCATION, trusted=True
)
TRUSTED_CERTIFICATE_STORE_WITH_CTL = FileSystemCertificateStore(
    location=CERTIFICATE_LOCATION,
    trusted=True,
    ctl=CertificateTrustList.from_stl_file(),
)
LEGACY_TRUSTED_CERTIFICATE_STORE = FileSystemCertificateStore(
    location=LEGACY_CERTIFICATES_LOCATION,
    trusted=True,
    ctl=LEGACY_CERTIFICATES,
)
TRUSTED_CERTIFICATE_STORE = (
    TRUSTED_CERTIFICATE_STORE_WITH_CTL | LEGACY_TRUSTED_CERTIFICATE_STORE
)


if __name__ == "__main__":
    print(
        "This is a list of all certificates in the Authenticode trust store, ordered by"
        " expiration date"
    )
    for i, certificate in enumerate(
        sorted(TRUSTED_CERTIFICATE_STORE, key=lambda x: x.valid_to), start=1
    ):
        print(i, certificate.valid_to, certificate)
