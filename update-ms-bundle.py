"""This script downloads and parses all certificates that are in the official Microsoft trust store, as maintained by
Mozilla's CCADB, as mentioned on https://docs.microsoft.com/en-us/security/trusted-root/participants-list and listed
on https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFT.
"""

import concurrent.futures
import csv
import pathlib
import requests
import asn1crypto.pem

from signify.authroot import CertificateTrustList

CERT_URL = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/{}.crt"
BUNDLE_PATH = pathlib.Path(__file__).resolve().parent / "signify" / "certs" / "authenticode-bundle.pem"
CACHE_PATH = pathlib.Path(__file__).resolve().parent / ".cache" / "certs"
CACHE_PATH.mkdir(parents=True, exist_ok=True)

# First fetch all data
CertificateTrustList.update_stl_file()
ctl = CertificateTrustList.from_stl_file()
print("Fetched CTL file, there are {} subjects".format(len(ctl.subjects)))


def check_certificate_in_cache(identifier):
    if not (CACHE_PATH / identifier).exists():
        return False
    with open(CACHE_PATH / identifier, "r") as cert_file:
        content = cert_file.read()
        if "-----END CERTIFICATE-----" not in content:
            print("Invalid cached certificate, adding {} again".format(identifier))
            return False
    return True


def fetch_certificate(identifier):
    r = requests.get(CERT_URL.format(identifier))
    r.raise_for_status()
    with open(CACHE_PATH / identifier, "wb") as f:
        f.write(asn1crypto.pem.armor("CERTIFICATE", r.content))
    print("- Fetched certificate {}".format(identifier))


def readable_eku(eku):
    from asn1crypto.x509 import KeyPurposeId
    return KeyPurposeId._map.get(".".join(map(str, eku)), ".".join(map(str, eku)))


for i, subject in enumerate(ctl.subjects):
    print(subject.friendly_name, "{} / {}".format(i+1, len(ctl.subjects)))

    if check_certificate_in_cache(subject.identifier.hex()):
        continue
    fetch_certificate(subject.identifier.hex())

with open(BUNDLE_PATH, "w", encoding='utf-8') as f:
    for subject in ctl.subjects:
        with open(CACHE_PATH / subject.identifier.hex(), "r") as cert_file:
            certificate_body = cert_file.read()

        f.write("Subject Identifier: {}\n".format(subject.identifier.hex()))
        if subject.friendly_name:
            f.write("Friendly Name: {}\n".format(subject.friendly_name[:-1]))
        if subject.extended_key_usages:
            f.write("Extended key usages: {}\n".format([readable_eku(x) for x in subject.extended_key_usages]))
        if subject.subject_name_md5:
            f.write("Subject Name MD5: {}\n".format(subject.subject_name_md5.hex()))
        if subject.disallowed_filetime:
            f.write("Disallowed Filetime: {}\n".format(subject.disallowed_filetime))
        if subject.root_program_chain_policies:
            f.write("Root Program Chain Policies: {}\n".format(
                [readable_eku(x) for x in subject.root_program_chain_policies]))
        if subject.disallowed_extended_key_usages:
            f.write("Disallowed extended key usages: {}\n".format(
                [readable_eku(x) for x in subject.disallowed_extended_key_usages]))
        if subject.not_before_filetime:
            f.write("Not before Filetime: {}\n".format(subject.not_before_filetime))
        if subject.not_before_extended_key_usages:
            f.write("Not before extended key usages: {}\n".format(
                [readable_eku(x) for x in subject.not_before_extended_key_usages]))

        f.write(certificate_body)
        f.write("\n")
