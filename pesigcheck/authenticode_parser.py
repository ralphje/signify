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

"""This module effectively implements the first few chapters of Microsoft's documentation on Authenticode_PE_.

.. _Authenticode_PE: http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
"""

import hashlib
from pyasn1.codec.ber import decoder
from pyasn1.type import univ

from . import asn1

ACCEPTED_DIGEST_ALGORITHMS = (hashlib.md5, hashlib.sha1)


class AuthenticodeParseError(Exception):
    pass


class AuthenticodeVerificationError(Exception):
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
    def __init__(self, data, signed_data):
        self.data = data
        self.signed_data = signed_data
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

    def get_issuing_certificates(self):
        yield from self.signed_data._find_certificates(subject=self.issuer)

    def is_self_signed(self):
        return self.subject == self.issuer


class SignerInfo(object):
    _expected_content_type = asn1.spc.SpcIndirectDataContent
    _required_authenticated_attributes = (asn1.pkcs7.ContentType, asn1.pkcs7.Digest, asn1.spc.SpcSpOpusInfo)

    def __init__(self, data, signed_data):
        self.data = data
        self.signed_data = signed_data
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

            self.countersigner = CounterSignerInfo(self.unauthenticated_attributes[asn1.pkcs7.CountersignInfo][0],
                                                   signed_data=self.signed_data)

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

    def get_issuing_certificates(self):
        yield from self.signed_data._find_certificates(issuer=self.issuer, serial_number=self.serial_number)


class CounterSignerInfo(SignerInfo):
    _required_authenticated_attributes = (asn1.pkcs7.ContentType, asn1.pkcs7.SigningTime, asn1.pkcs7.Digest)
    _expected_content_type = asn1.pkcs7.Data


class SpcInfo(object):
    def __init__(self, data, signed_data):
        self.data = data
        self.signed_data = signed_data
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
    def __init__(self, data, pefile=None):
        self.data = data
        self.pefile = pefile
        self._parse()

    @classmethod
    def from_certificate(cls, data, *args, **kwargs):
        # This one is not guarded, which is intentional
        content, rest = decoder.decode(data, asn1Spec=asn1.pkcs7.ContentInfo())
        if asn1.oids.get(content['contentType']) is not asn1.pkcs7.SignedData:
            raise AuthenticodeParseError("ContentInfo does not contain SignedData")

        data = _guarded_ber_decode(content['content'], asn1_spec=asn1.pkcs7.SignedData())

        signed_data = SignedData(data, *args, **kwargs)
        signed_data._rest_data = rest
        return signed_data

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
        self.spc_info = SpcInfo(spc_info, signed_data=self)

        # Certificates
        self.certificates = [Certificate(cert, signed_data=self) for cert in self.data['certificates']]

        # signerInfos
        if len(self.data['signerInfos']) != 1:
            raise AuthenticodeParseError("SignedData.signerInfos must contain exactly 1 signer, not %d" %
                                         len(self.data['signerInfos']))

        self.signer_info = SignerInfo(self.data['signerInfos'][0], signed_data=self)

        # CRLs
        if 'crls' in self.data and self.data['crls'].isValue:
            raise AuthenticodeParseError("SignedData.crls is present, but that is unexpected.")

    def _find_certificates(self, *, subject=None, serial_number=None, issuer=None):
        for certificate in self.certificates:
            if subject is not None and certificate.subject != subject:
                continue
            if serial_number is not None and certificate.serial_number != serial_number:
                continue
            if issuer is not None and certificate.issuer != issuer:
                continue
            yield certificate

    def verify(self, expected_hash=None):
        # Check that the digest algorithms match
        if self.digest_algorithm != self.spc_info.digest_algorithm:
            raise AuthenticodeVerificationError("SignedData.digestAlgorithm must equal SpcInfo.digestAlgorithm")

        if self.digest_algorithm != self.signer_info.digest_algorithm:
            raise AuthenticodeVerificationError("SignedData.digestAlgorithm must equal SignerInfo.digestAlgorithm")

        # Check that the hashes are correct
        # 1. The hash of the file
        if expected_hash is None:
            fingerprinter = self.pefile.get_fingerprinter()
            fingerprinter.add_authenticode_hashers(self.digest_algorithm)
            expected_hash = fingerprinter.hash()[self.digest_algorithm().name]

        if expected_hash != self.spc_info.digest:
            raise AuthenticodeVerificationError("The expected hash does not match the digest in SpcInfo")

        # 2. The hash of the spc blob
        # According to RFC2315, 9.3, identifier (tag) and length need to be
        # stripped for hashing. We do this by having the parser just strip
        # out the SEQUENCE part of the spcIndirectData.
        # Alternatively this could be done by re-encoding and concatenating
        # the individual elements in spc_value, I _think_.
        _, hashable_spc_blob = decoder.decode(self.data['contentInfo']['content'], recursiveFlag=0)
        spc_blob_hash = self.digest_algorithm(bytes(hashable_spc_blob)).digest()
        if spc_blob_hash != self.signer_info.message_digest:
            raise AuthenticodeVerificationError('The expected hash of the SpcInfo does not match SignerInfo')

        # TODO:
        # Can't check authAttr hash against encrypted hash, done implicitly in
        # M2's pubkey.verify. This can be added by explicit decryption of
        # encryptedDigest, if really needed. (See sample code for RSA in
        # 'verbose_authenticode_sig.py')

        if self.signer_info.countersigner:
            auth_attr_hash = self.digest_algorithm(self.signer_info.encrypted_digest).digest()
            if auth_attr_hash != self.signer_info.countersigner.message_digest:
                raise AuthenticodeVerificationError('The expected hash of the encryptedDigest does not match '
                                                    'countersigner\'s SignerInfo')
