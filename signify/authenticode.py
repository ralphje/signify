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

"""This module effectively implements Microsoft's documentation on Authenticode_PE_.

.. _Authenticode_PE: http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
"""

import hashlib
import logging
import pathlib

from pyasn1.codec.ber import decoder as ber_decoder

from signify.asn1 import guarded_ber_decode
from signify.certificates import Certificate
from signify.context import CertificateStore, VerificationContext, FileSystemCertificateStore
from signify.exceptions import AuthenticodeParseError, AuthenticodeVerificationError
from signify.signerinfo import _get_digest_algorithm, SignerInfo, CounterSignerInfo
from . import asn1

logger = logging.getLogger(__name__)

ACCEPTED_DIGEST_ALGORITHMS = (hashlib.md5, hashlib.sha1)
CERTIFICATE_LOCATION = pathlib.Path(__file__).resolve().parent.parent / "certificates" / "authenticode"


class AuthenticodeCounterSignerInfo(CounterSignerInfo):
    """Subclass of CounterSignerInfo that is used to contain the countersignerinfo for Authenticode."""

    _required_authenticated_attributes = (asn1.pkcs7.ContentType, asn1.pkcs7.SigningTime, asn1.pkcs7.Digest)
    _expected_content_type = asn1.pkcs7.Data


class AuthenticodeSignerInfo(SignerInfo):
    """Subclass of SignerInfo that is used to contain the signerinfo for Authenticode."""

    _countersigner_class = AuthenticodeCounterSignerInfo
    _expected_content_type = asn1.spc.SpcIndirectDataContent
    _required_authenticated_attributes = (asn1.pkcs7.ContentType, asn1.pkcs7.Digest, asn1.spc.SpcSpOpusInfo)

    def _parse(self):
        super()._parse()

        # - Retrieve object from SpcSpOpusInfo from the authenticated attributes (for normal signer)
        self.program_name = self.more_info = None
        if asn1.spc.SpcSpOpusInfo in self.authenticated_attributes:
            if len(self.authenticated_attributes[asn1.spc.SpcSpOpusInfo]) != 1:
                raise AuthenticodeParseError("Only one SpcSpOpusInfo expected in SignerInfo.authenticatedAttributes")

            self.program_name = self.authenticated_attributes[asn1.spc.SpcSpOpusInfo][0]['programName'].to_python()
            self.more_info = str(self.authenticated_attributes[asn1.spc.SpcSpOpusInfo][0]['moreInfo']['url'])


class SpcInfo(object):
    def __init__(self, data):
        """The Authenticode's SpcIndirectDataContent information, and their children. It is only partially parsed."""

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
    def __init__(self, data, pefile=None):
        """The SignedData object of Authenticode. It is the root of all Authenticode related information.

        :param asn1.pkcs7.SignedData data: The ASN.1 structure of the SignedData object
        :param pefile: The related PEFile.
        """

        self.data = data
        self.pefile = pefile
        self._parse()

    @classmethod
    def from_certificate(cls, data, *args, **kwargs):
        """Loads a :class:`SignedData` object from raw data that contains ContentInfo.

        :param bytes data: The bytes to parse
        """
        # This one is not guarded, which is intentional
        content, rest = ber_decoder.decode(data, asn1Spec=asn1.pkcs7.ContentInfo())
        if asn1.oids.get(content['contentType']) is not asn1.pkcs7.SignedData:
            raise AuthenticodeParseError("ContentInfo does not contain SignedData")

        data = guarded_ber_decode(content['content'], asn1_spec=asn1.pkcs7.SignedData())

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
        spc_info = guarded_ber_decode(self.data['contentInfo']['content'], asn1_spec=asn1.spc.SpcIndirectDataContent())
        self.spc_info = SpcInfo(spc_info)

        # Certificates
        self.certificates = CertificateStore([Certificate(cert) for cert in self.data['certificates']])

        # signerInfos
        if len(self.data['signerInfos']) != 1:
            raise AuthenticodeParseError("SignedData.signerInfos must contain exactly 1 signer, not %d" %
                                         len(self.data['signerInfos']))

        self.signer_info = AuthenticodeSignerInfo(self.data['signerInfos'][0])

        # CRLs
        if 'crls' in self.data and self.data['crls'].isValue:
            raise AuthenticodeParseError("SignedData.crls is present, but that is unexpected.")

    def verify(self, expected_hash=None, verification_context=None, cs_verification_context=None):
        """Verifies the SignedData structure:

        * Verifies that the digest algorithms match across the structure
        * Ensures that the hash in the :class:`SpcInfo` structure matches the expected hash. If no expected hash is
          provided to this function, it is calculated using the :class:`Fingerprinter` obtained from the
          :class:`SignedPEFile` object.
        * Verifies that the SpcInfo is signed by the :class:`SignerInfo`
        * In the case of a countersigner, verifies that the :class:`CounterSignerInfo` has the hashed encrypted digest
          of the :class:`SignerInfo`
        * Verifies the chain of the countersigner up to a trusted root
        * Verifies the chain of the signer up to a trusted root

        In the case of a countersigner, the verification is performed using the timestamp of the
        :class:`CounterSignerInfo`, otherwise now is assumed. If there is no countersigner, you can override this
        by specifying a different timestamp in the :class:`VerificationContext`

        :param bytes expected_hash: The expected hash digest of the :class:`SignedPEFile`.
        :param VerificationContext verification_context: The VerificationContext for verifying the chain of the
            :class:`SignerInfo`. The timestamp is overridden in the case of a countersigner.
        :param VerificationContext cs_verification_context: The VerificationContext for verifying the chain of the
            :class:`CounterSignerInfo`. The timestamp is overridden in the case of a countersigner.
        :raises AuthenticodeVerificationError: when the verification failed
        :return: :const:`None`
        """

        trusted_certificate_store = FileSystemCertificateStore(location=CERTIFICATE_LOCATION, trusted=True)

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
        _, hashable_spc_blob = ber_decoder.decode(self.data['contentInfo']['content'], recursiveFlag=0)
        spc_blob_hash = self.digest_algorithm(bytes(hashable_spc_blob)).digest()
        if spc_blob_hash != self.signer_info.message_digest:
            raise AuthenticodeVerificationError('The expected hash of the SpcInfo does not match SignerInfo')

        # Can't check authAttr hash against encrypted hash, done implicitly in
        # M2's pubkey.verify.

        # 3. Check the countersigner hash.
        if self.signer_info.countersigner:
            auth_attr_hash = self.digest_algorithm(self.signer_info.encrypted_digest).digest()
            if auth_attr_hash != self.signer_info.countersigner.message_digest:
                raise AuthenticodeVerificationError('The expected hash of the encryptedDigest does not match '
                                                    'countersigner\'s SignerInfo')

        if verification_context is None:
            verification_context = VerificationContext(trusted_certificate_store, self.certificates,
                                                       extended_key_usages=['code_signing'])

        if self.signer_info.countersigner:
            if cs_verification_context is None:
                cs_verification_context = VerificationContext(trusted_certificate_store, self.certificates,
                                                              extended_key_usages=['time_stamping'])
            cs_verification_context.timestamp = self.signer_info.countersigner.signing_time

            self.signer_info.countersigner.verify(cs_verification_context)

            # TODO: What to do when the verification fails? Check it as if the countersignature is not present?
            # Or fail all together? (Which is done now)
            verification_context.timestamp = self.signer_info.countersigner.signing_time

        self.signer_info.verify(verification_context)
