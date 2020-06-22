"""This script downloads and parses all certificates that are in the official Microsoft trust store, as maintained by
Mozilla's CCADB, as mentioned on https://docs.microsoft.com/en-us/security/trusted-root/participants-list and listed
on https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFT.
"""

import concurrent.futures
import csv
import pathlib
import requests


CCADB_URL = "https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV"
CERT_URL = "https://crt.sh/?d={}"
BUNDLE_PATH = pathlib.Path(__file__).resolve().parent / "signify" / "certs" / "authenticode-bundle.pem"
CACHE_PATH = pathlib.Path(__file__).resolve().parent / ".cache" / "certs"
CACHE_PATH.mkdir(parents=True, exist_ok=True)

# First fetch all data
ccadb_data = []
certs_to_fetch = set()
with requests.get(CCADB_URL, stream=True) as r:
    r.raise_for_status()
    lines = (line.decode('utf-8') for line in r.iter_lines())
    for row in csv.DictReader(lines):
        ccadb_data.append(row)
        if not (CACHE_PATH / row['SHA-256 Fingerprint']).exists():
            certs_to_fetch.add(row['SHA-256 Fingerprint'])
        else:
            with open(CACHE_PATH / row['SHA-256 Fingerprint'], "r") as cert_file:
                content = cert_file.read()
                if "-----END CERTIFICATE-----" not in content:
                    print("Invalid cached certificate, adding {} again".format(row['SHA-256 Fingerprint']))
                    certs_to_fetch.add(row['SHA-256 Fingerprint'])

print("Fetched CSV file, there are {} entries".format(len(ccadb_data)))


# Second make sure we have all the certificates we need
def fetch_certificate(sha256):
    r = requests.get(CERT_URL.format(sha256))
    r.raise_for_status()
    with open(CACHE_PATH / sha256, "w") as f:
        f.write(r.text)
    print("- Fetched certificate {}".format(sha256))


print("Need to fetch {} certificates to cache".format(len(certs_to_fetch)))
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    futures = [executor.submit(fetch_certificate, sha256) for sha256 in certs_to_fetch]
    concurrent.futures.wait(futures)
    print("Fetched {} certificates to cache".format(len(futures)))


# Thirdly, add all certificates to the bundle file
with open(BUNDLE_PATH, "w", encoding='utf-8') as f:
    for row in ccadb_data:
        print("{CA Owner} - {CA Common Name or Certificate Name}".format(**row))

        with open(CACHE_PATH / row['SHA-256 Fingerprint'], "r") as cert_file:
            certificate_body = cert_file.read()

        for k, v in row.items():
            f.write("{k}: {v}\n".format(k=k, v=v))
        f.write(certificate_body)
        f.write("\n")
