# This is a derivative, modified, work from the verify-sigs project.
# Please refer to the LICENSE file in the distribution for more
# information. Original filename: asn1/oids.py
#
# Parts of this file are licensed as follows:
#
# Copyright 2011 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""ASN.1 OIDs mappings to parser classes or strings, where there is no class."""

import hashlib

from pyasn1_modules import rfc3161, rfc5652, rfc2315

from . import pkcs7, spc

OID_TO_CLASS = {
    (1, 2, 840, 113549, 1, 7, 1): pkcs7.Data,
    (1, 2, 840, 113549, 1, 7, 2): rfc2315.SignedData,
    (1, 2, 840, 113549, 2, 5): hashlib.md5,
    (1, 3, 14, 3, 2, 26): hashlib.sha1,
    (2, 16, 840, 1, 101, 3, 4, 2, 1): hashlib.sha256,
    (1, 3, 6, 1, 4, 1, 311, 2, 1, 4): spc.SpcIndirectDataContent,
    (1, 2, 840, 113549, 1, 9, 3): rfc2315.ContentType,
    (1, 2, 840, 113549, 1, 9, 4): rfc2315.Digest,
    # (1, 3, 6, 1, 4, 1, 311, 2, 1, 11): spc.SpcStatementType,  # TODO: test and verify
    (1, 3, 6, 1, 4, 1, 311, 2, 1, 12): spc.SpcSpOpusInfo,
    (1, 2, 840, 113549, 1, 9, 6): pkcs7.Countersignature,  # 'RSA_counterSign'
    (1, 2, 840, 113549, 1, 9, 5): rfc5652.SigningTime,
    (1, 3, 6, 1, 4, 1, 311, 3, 3, 1): spc.SpcRfc3161Timestamp,
    (1, 2, 840, 113549, 1, 9, 16, 1, 4): rfc3161.TSTInfo,
}

OID_TO_PUBKEY = {
    (1, 2, 840, 113549, 1, 1, 1): 'rsa',
    (1, 2, 840, 113549, 1, 1, 5): 'rsa-sha1',
    (1, 2, 840, 10040, 4, 1): 'dsa',
    (1, 2, 840, 10040, 4, 3): 'dsa-sha1',
    (1, 2, 840, 10045, 4, 1): 'ecdsa-sha1',
    (1, 2, 840, 10045, 4, 3, 1): 'ecdsa-sha224',
    (1, 2, 840, 10045, 4, 3, 2): 'ecdsa-sha256',
    (1, 2, 840, 10045, 4, 3, 3): 'ecdsa-sha384',
    (1, 2, 840, 10045, 4, 3, 4): 'ecdsa-sha512',
}

OID_TO_RDN = {
    (2, 5, 4, 3): 'CN',  # common name
    (2, 5, 4, 6): 'C',  # country
    (2, 5, 4, 7): 'L',  # locality
    (2, 5, 4, 8): 'ST',  # stateOrProvince
    (2, 5, 4, 9): 'STREET',  # street
    (2, 5, 4, 10): 'O',  # organization
    (2, 5, 4, 11): 'OU',  # organizationalUnit
    (0, 9, 2342, 19200300, 100, 1, 25): 'DC',  # domainComponent
    (1, 2, 840, 113549, 1, 9, 1): 'EMAIL',  # emailaddress
}

EKU_CODE_SIGNING = (1, 3, 6, 1, 5, 5, 7, 3, 3)  # codeSigning
EKU_TIME_STAMPING = (1, 3, 6, 1, 5, 5, 7, 3, 8)  # timeStamping


def get(key, oids=OID_TO_CLASS):
    return oids.get(key, tuple(key))
