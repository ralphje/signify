# This script generates the legacy-certs.pem bundle, allowing proof of how this file
# has come together.
import pathlib

import asn1crypto.pem
import requests

from signify.authenticode.cert_store import LEGACY_CERTIFICATES
from signify.x509 import Certificate

HEADER = """
The certificates in this file have not been added by Microsoft to the CCADB with
trusted certificates and is probably no longer part of its Microsoft Trusted Root
Program. However, they still appear as trusted in modern Windows installations and are
required for older components. These certificates are listed on
https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/trusted-root-certificates-are-required
"""

CERT_URL = (
    "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/{}.crt"
)


BUNDLE = pathlib.Path(__file__).parent / "signify" / "authenticode" / "legacy-certs.pem"

with BUNDLE.open("w") as f:
    f.write(HEADER.strip())

    for cert in LEGACY_CERTIFICATES:
        print(cert)
        certificate_r = requests.get(CERT_URL.format(cert))
        certificate_r.raise_for_status()
        armored = asn1crypto.pem.armor("CERTIFICATE", certificate_r.content)
        cert = Certificate.from_pem(armored)
        f.write(f"\n\nSubject: {cert.subject}\n")
        f.write(f"Serial: {cert.serial_number:x}\n")
        f.write(f"Expiration: {cert.valid_to}\n")
        f.write(f"SHA-1: {cert.sha1_fingerprint}\n")
        f.write(f"SHA-256: {cert.sha256_fingerprint}\n")
        f.write(armored.decode())
