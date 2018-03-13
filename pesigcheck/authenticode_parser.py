#!/usr/bin/env python

# This is a derivative, modified, work from the verify-sigs project.
# Please refer to the LICENSE file in the distribution for more
# information. Original filename: auth_data.py
#
# Parts of this file are licensed as follows:
#
# Copyright 2010 Google Inc. All Rights Reserved.
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

import hashlib
from pyasn1.codec.ber import decoder
from pyasn1.type import univ

from . import asn1

ACCEPTED_DIGEST_ALGORITHMS = (hashlib.md5, hashlib.sha1)


class AuthenticodeParseError(Exception):
    pass


def _print_type(t):
    if t is None:
        return ""
    elif isinstance(t, tuple):
        return ".".join(t)
    elif hasattr(t, "__name__"):
        return t.__name__
    else:
        return type(t).__name__


def _guarded_ber_decode(data, asn1_spec=None):
    result, rest = decoder.decode(data, asn1Spec=asn1_spec)
    if rest:
        raise AuthenticodeParseError("Extra information after parsing %s BER" % _print_type(asn1_spec))
    return result


def _verify_empty_algorithm_parameters(algorithm, location):
    if 'parameters' in algorithm and algorithm['parameters'].isValue:
        parameters = _guarded_ber_decode(algorithm['parameters'])
        if not isinstance(parameters, univ.Null):
            raise AuthenticodeParseError("%s has parameters set, which is unexpected" % (location,))


def _get_digest_algorithm(algorithm, location):
    result = asn1.oids.get(algorithm['algorithm'])
    if result not in ACCEPTED_DIGEST_ALGORITHMS:
        raise AuthenticodeParseError("%s must be one of %s, not %s" %
                                     (location, [x().name for x in ACCEPTED_DIGEST_ALGORITHMS], result().name))

    _verify_empty_algorithm_parameters(algorithm, location)
    return result


def _get_encryption_algorithm(algorithm, location):
    result = asn1.oids.OID_TO_PUBKEY.get(algorithm['algorithm'])
    if result is None:
        raise AuthenticodeParseError("%s: %s is not acceptable as encryption algorithm" %
                                     (location, algorithm['algorithm']))

    _verify_empty_algorithm_parameters(algorithm, location)
    return result


class Certificate(object):
    def __init__(self, data):
        self.data = data
        self._parse()

    def _parse(self):
        if 'extendedCertificate' in self.data:
            # TODO: Not sure if needed.
            raise NotImplementedError("Support for extendedCertificate is not implemented")

        certificate = self.data['certificate']
        self.signature_algorithm = certificate['signatureAlgorithm']
        self.signature_value = certificate['signatureValue']

        tbs_certificate = certificate['tbsCertificate']
        self.version = tbs_certificate['version']
        self.serial_number = tbs_certificate['serialNumber']
        self.issuer = tbs_certificate['issuer'][0]
        self.issuer_dn = tbs_certificate['issuer'][0].to_string()
        self.valid_from = tbs_certificate['validity']['notBefore'].to_python_time()
        self.valid_to = tbs_certificate['validity']['notAfter'].to_python_time()
        self.subject = tbs_certificate['subject'][0]
        self.subject_dn = tbs_certificate['subject'][0].to_string()

        self.subject_public_algorithm = tbs_certificate['subjectPublicKeyInfo']['algorithm']
        self.subject_public_key = tbs_certificate['subjectPublicKeyInfo']['subjectPublicKey']

        self.issuer_unique_id = tbs_certificate['issuerUniqueID'] \
            if 'issuerUniqueID' in tbs_certificate and tbs_certificate['issuerUniqueID'].isValue else None
        self.subject_unique_id = tbs_certificate['subjectUniqueID'] \
            if 'subjectUniqueID' in tbs_certificate and tbs_certificate['subjectUniqueID'].isValue else None

        self.extensions = {}
        if 'extensions' in tbs_certificate and tbs_certificate['extensions'].isValue:
            for extension in tbs_certificate['extensions']:
                self.extensions[asn1.oids.get(extension['extnID'])] = extension['extnValue']


class SignerInfo(object):
    _expected_content_type = asn1.spc.SpcIndirectDataContent
    _required_authenticated_attributes = (asn1.pkcs7.ContentType, asn1.pkcs7.Digest, asn1.spc.SpcSpOpusInfo)

    def __init__(self, data):
        self.data = data
        self._parse()

    def _parse(self):
        if self.data['version'] != 1:
            raise AuthenticodeParseError("SignerInfo.version must be 1, not %d" % self.data['version'])

        self.issuer = self.data['issuerAndSerialNumber']['issuer']
        self.issuer_dn = self.data['issuerAndSerialNumber']['issuer'][0].to_string()
        self.serial_number = self.data['issuerAndSerialNumber']['serialNumber']

        self.digest_algorithm = _get_digest_algorithm(self.data['digestAlgorithm'],
                                                      location="SignerInfo.digestAlgorithm")

        self.authenticated_attributes = self._parse_attributes(
            self.data['authenticatedAttributes'],
            required=self._required_authenticated_attributes
        )

        # Parse the content of the authenticated attributes
        # - Retrieve object from SpcSpOpusInfo from the authenticated attributes (for normal signer)
        self.program_name = self.more_info = None
        if asn1.spc.SpcSpOpusInfo in self.authenticated_attributes:
            if len(self.authenticated_attributes[asn1.spc.SpcSpOpusInfo]) != 1:
                raise AuthenticodeParseError("Only one SpcSpOpusInfo expected in SignerInfo.authenticatedAttributes")

            self.program_name = self.authenticated_attributes[asn1.spc.SpcSpOpusInfo][0]['programName'].to_python()
            self.more_info = str(self.authenticated_attributes[asn1.spc.SpcSpOpusInfo][0]['moreInfo']['url'])

        # - The messageDigest
        self.message_digest = None
        if asn1.pkcs7.Digest in self.authenticated_attributes:
            if len(self.authenticated_attributes[asn1.pkcs7.Digest]) != 1:
                raise AuthenticodeParseError("Only one Digest expected in SignerInfo.authenticatedAttributes")

            self.message_digest = bytes(self.authenticated_attributes[asn1.pkcs7.Digest][0])

        # - The contentType
        self.content_type = None
        if asn1.pkcs7.ContentType in self.authenticated_attributes:
            if len(self.authenticated_attributes[asn1.pkcs7.ContentType]) != 1:
                raise AuthenticodeParseError("Only one ContentType expected in SignerInfo.authenticatedAttributes")

            self.content_type = asn1.oids.get(self.authenticated_attributes[asn1.pkcs7.ContentType][0])

            if self.content_type is not self._expected_content_type:
                raise AuthenticodeParseError("Unexpected content type for SignerInfo, expected %s, got %s" %
                                             (_print_type(self.content_type),
                                            _print_type(self._expected_content_type)))

        # - The signingTime (used by countersigner)
        self.signing_time = None
        if asn1.pkcs7.SigningTime in self.authenticated_attributes:
            if len(self.authenticated_attributes[asn1.pkcs7.SigningTime]) != 1:
                raise AuthenticodeParseError("Only one SigningTime expected in SignerInfo.authenticatedAttributes")

            self.signing_time = self.authenticated_attributes[asn1.pkcs7.SigningTime][0].to_python_time()

        # Continue with the other attributes of the SignerInfo object
        self.digest_encryption_algorithm = _get_encryption_algorithm(self.data['digestEncryptionAlgorithm'],
                                                                     location="SignerInfo.digestEncryptionAlgorithm")

        self.encrypted_digest = bytes(self.data['encryptedDigest'])

        self.unauthenticated_attributes = self._parse_attributes(self.data['unauthenticatedAttributes'])

        # - The countersigner
        self.countersigner = None
        if asn1.pkcs7.CountersignInfo in self.unauthenticated_attributes:
            if len(self.unauthenticated_attributes[asn1.pkcs7.CountersignInfo]) != 1:
                raise AuthenticodeParseError("Only one CountersignInfo expected in SignerInfo.unauthenticatedAttributes")

            self.countersigner = CounterSignerInfo(self.unauthenticated_attributes[asn1.pkcs7.CountersignInfo][0])

    @classmethod
    def _parse_attributes(cls, data, required=()):
        result = {}
        for attr in data:
            typ = asn1.oids.get(attr['type'])
            values = []
            for value in attr['values']:
                value = _guarded_ber_decode(value, asn1_spec=typ() if not isinstance(typ, tuple) else None)
                values.append(value)
            result[typ] = values

        if not all((x in result for x in required)):
            raise AuthenticodeParseError("Not all required attributes found. Required: %s; Found: %s" %
                                         ([_print_type(x) for x in required], [_print_type(x) for x in result]))

        return result


class CounterSignerInfo(SignerInfo):
    _required_authenticated_attributes = (asn1.pkcs7.ContentType, asn1.pkcs7.SigningTime, asn1.pkcs7.Digest)
    _expected_content_type = asn1.pkcs7.Data


class SpcInfo(object):
    def __init__(self, data):
        self.data = data
        self._parse()

    def _parse(self):
        # The data attribute
        self.content_type = asn1.oids.OID_TO_CLASS.get(self.data['data']['type'])
        self.image_data = None
        if 'value' in self.data['data'] and self.data['data']['value'].isValue:
            self.image_data = None
            # TODO: not parsed
            #image_data = _guarded_ber_decode((self.data['data']['value'], asn1_spec=self.content_type())

        self.digest_algorithm = _get_digest_algorithm(self.data['messageDigest']['digestAlgorithm'],
                                                      location="SpcIndirectDataContent.digestAlgorithm")

        self.digest = bytes(self.data['messageDigest']['digest'])


class SignedData(object):
    def __init__(self, data):
        self.data = data
        self._parse()

    @classmethod
    def from_certificate(cls, data):
        content = _guarded_ber_decode(data, asn1_spec=asn1.pkcs7.ContentInfo())
        if asn1.oids.get(content['contentType']) is not asn1.pkcs7.SignedData:
            raise AuthenticodeParseError("ContentInfo does not contain SignedData")

        data = _guarded_ber_decode(content['content'], asn1_spec=asn1.pkcs7.SignedData())

        return SignedData(data)

    def _parse(self):
        # Parse the fields of the SignedData structure
        if self.data['version'] != 1:
            raise AuthenticodeParseError("SignedData.version must be 1, not %d" % self.data['version'])

        # digestAlgorithms
        if len(self.data['digestAlgorithms']) != 1:
            raise AuthenticodeParseError("SignedData.digestAlgorithms must contain exactly 1 algorithm, not %d" %
                                         len(self.data['digestAlgorithms']))
        self.digest_algorithm = _get_digest_algorithm(self.data['digestAlgorithms'][0], "SignedData.digestAlgorithm")

        # SpcIndirectDataContent
        self.content_type = asn1.oids.get(self.data['contentInfo']['contentType'])
        if self.content_type is not asn1.spc.SpcIndirectDataContent:
            raise AuthenticodeParseError("SignedData.contentInfo does not contain SpcIndirectDataContent")
        spc_info = _guarded_ber_decode(self.data['contentInfo']['content'], asn1_spec=asn1.spc.SpcIndirectDataContent())
        self.spc_info = SpcInfo(spc_info)

        # Certificates
        self.certificates = [Certificate(cert) for cert in self.data['certificates']]

        # signerInfos
        if len(self.data['signerInfos']) != 1:
            raise AuthenticodeParseError("SignedData.signerInfos must contain exactly 1 signer, not %d" %
                                         len(self.data['signerInfos']))

        self.signer_info = SignerInfo(self.data['signerInfos'][0])
