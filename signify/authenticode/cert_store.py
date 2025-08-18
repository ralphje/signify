import pathlib

import mscerts

from signify.authenticode.trust_list import CertificateTrustList
from signify.x509 import FileSystemCertificateStore

CERTIFICATE_LOCATION = pathlib.Path(mscerts.where(stl=False))
TRUSTED_CERTIFICATE_STORE_NO_CTL = FileSystemCertificateStore(
    location=CERTIFICATE_LOCATION, trusted=True
)
TRUSTED_CERTIFICATE_STORE = FileSystemCertificateStore(
    location=CERTIFICATE_LOCATION,
    trusted=True,
    ctl=CertificateTrustList.from_stl_file(),
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
