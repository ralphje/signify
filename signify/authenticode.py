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

import logging
import pathlib

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1_modules import rfc3161, rfc2315, rfc5652

from signify.asn1 import guarded_ber_decode, guarded_der_decode, pkcs7
from signify.asn1.helpers import accuracy_to_python, patch_rfc5652_signeddata
from signify.certificates import Certificate, CertificateName
from signify.context import CertificateStore, VerificationContext, FileSystemCertificateStore
from signify.exceptions import AuthenticodeParseError, AuthenticodeVerificationError, ParseError
from signify.signeddata import SignedData
from signify.signerinfo import _get_digest_algorithm, SignerInfo, CounterSignerInfo
from signify import asn1

logger = logging.getLogger(__name__)

CERTIFICATE_LOCATION = pathlib.Path(__file__).resolve().parent / "certs" / "authenticode-bundle.pem"
TRUSTED_CERTIFICATE_STORE = FileSystemCertificateStore(location=CERTIFICATE_LOCATION, trusted=True)


class AuthenticodeCounterSignerInfo(CounterSignerInfo):
    """Subclass of CounterSignerInfo that is used to contain the countersignerinfo for Authenticode."""

    _required_authenticated_attributes = (rfc2315.ContentType, rfc5652.SigningTime, rfc2315.Digest)


class AuthenticodeSignerInfo(SignerInfo):
    """Subclass of SignerInfo that is used to contain the signerinfo for Authenticode."""

    _countersigner_class = AuthenticodeCounterSignerInfo
    _expected_content_type = asn1.spc.SpcIndirectDataContent
    _required_authenticated_attributes = (rfc2315.ContentType, rfc2315.Digest)

    def _parse(self):
        super()._parse()

        # - Retrieve object from SpcSpOpusInfo from the authenticated attributes (for normal signer)
        self.program_name = self.more_info = None
        if asn1.spc.SpcSpOpusInfo in self.authenticated_attributes:
            if len(self.authenticated_attributes[asn1.spc.SpcSpOpusInfo]) != 1:
                raise AuthenticodeParseError("Only one SpcSpOpusInfo expected in SignerInfo.authenticatedAttributes")

            self.program_name = self.authenticated_attributes[asn1.spc.SpcSpOpusInfo][0]['programName'].to_python()
            self.more_info = self.authenticated_attributes[asn1.spc.SpcSpOpusInfo][0]['moreInfo'].to_python()

        # - Authenticode can be signed using a RFC-3161 timestamp, so we discover this possibility here
        if pkcs7.Countersignature in self.unauthenticated_attributes \
                and asn1.spc.SpcRfc3161Timestamp in self.unauthenticated_attributes:
            raise AuthenticodeParseError("Countersignature and RFC-3161 timestamp present in "
                                         "SignerInfo.unauthenticatedAttributes")

        if asn1.spc.SpcRfc3161Timestamp in self.unauthenticated_attributes:
            if len(self.unauthenticated_attributes[asn1.spc.SpcRfc3161Timestamp]) != 1:
                raise AuthenticodeParseError("Only one RFC-3161 timestamp expected in "
                                             "SignerInfo.unauthenticatedAttributes")

            ts_data = self.unauthenticated_attributes[asn1.spc.SpcRfc3161Timestamp][0]
            content_type = asn1.oids.get(ts_data['contentType'])
            if content_type is not rfc2315.SignedData:
                raise AuthenticodeParseError("RFC-3161 Timestamp does not contain SignedData structure")
            # Note that we expect rfc5652 compatible data here
            # This is a work-around for incorrectly tagged v2AttrCerts in the BER-encoded blob,
            # see the docstring for patch_rfc5652_signeddata for more details
            try:
                signed_data = guarded_ber_decode(ts_data['content'], asn1_spec=rfc5652.SignedData())
            except ParseError:
                with patch_rfc5652_signeddata() as asn1_spec:
                    signed_data = guarded_ber_decode(ts_data['content'], asn1_spec=asn1_spec)
            self.countersigner = RFC3161SignedData(signed_data)


class SpcInfo:
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


class AuthenticodeSignedData(SignedData):
    _expected_content_type = asn1.spc.SpcIndirectDataContent
    _signerinfo_class = AuthenticodeSignerInfo

    def __init__(self, data, pefile=None):
        """The SignedData object of Authenticode. It is the root of all Authenticode related information.

        :param asn1.pkcs7.SignedData data: The ASN.1 structure of the SignedData object
        :param pefile: The related PEFile.
        """
        self.pefile = pefile
        super().__init__(data)

    def _parse(self):
        # Parse the fields of the SignedData structure
        if self.data['version'] != 1:
            raise AuthenticodeParseError("SignedData.version must be 1, not %d" % self.data['version'])

        super()._parse()
        self.spc_info = SpcInfo(self.content)

        # signerInfos
        if len(self.signer_infos) != 1:
            raise AuthenticodeParseError("SignedData.signerInfos must contain exactly 1 signer, not %d" %
                                         len(self.signer_infos))

        self.signer_info = self.signer_infos[0]

        # CRLs
        if 'crls' in self.data and self.data['crls'].isValue:
            raise AuthenticodeParseError("SignedData.crls is present, but that is unexpected.")

    def verify(self, expected_hash=None, verification_context=None, cs_verification_context=None,
               trusted_certificate_store=TRUSTED_CERTIFICATE_STORE, verification_context_kwargs={},
               allow_countersignature_errors=False):
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
            :class:`SignerInfo`. The timestamp is overridden in the case of a countersigner. Default stores are
            TRUSTED_CERTIFICATE_STORE and the certificates of this :class:`SignedData` object. EKU is code_signing
        :param VerificationContext cs_verification_context: The VerificationContext for verifying the chain of the
            :class:`CounterSignerInfo`. The timestamp is overridden in the case of a countersigner. Default stores are
            TRUSTED_CERTIFICATE_STORE and the certificates of this :class:`SignedData` object. EKU is time_stamping
        :param CertificateStore trusted_certificate_store: A :class:`CertificateStore` object that contains a list of
            trusted certificates to be used when :const:`None` is passed to either :param:`verification_context` or
            :param:`cs_verification_context` and a :class:`VerificationContext` is created.
        :param dict verification_context_kwargs: If provided, keyword arguments that are passed to the instantiation of
            :class:`VerificationContext`s created in this function. Used for e.g. providing a timestamp.
        :param bool allow_countersignature_errors: If this is set to True, errors in the countersignature cause the
            binary to be verified as if it was never countersigned
        :raises AuthenticodeVerificationError: when the verification failed
        :return: :const:`None`
        """

        if verification_context is None:
            verification_context = VerificationContext(trusted_certificate_store, self.certificates,
                                                       extended_key_usages=['code_signing'],
                                                       **verification_context_kwargs)

        if cs_verification_context is None and self.signer_info.countersigner:
            cs_verification_context = VerificationContext(trusted_certificate_store, self.certificates,
                                                          extended_key_usages=['time_stamping'],
                                                          **verification_context_kwargs)
            # Add the local certificate store for the countersignature (in the case of RFC3161SignedData)
            if hasattr(self.signer_info.countersigner, 'certificates'):
                cs_verification_context.add_store(self.signer_info.countersigner.certificates)

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

        if self.signer_info.countersigner:
            try:
                # 3. Check the countersigner hash.
                # Make sure to use the same digest_algorithm that the countersigner used
                if not self.signer_info.countersigner.check_message_digest(self.signer_info.encrypted_digest):
                    raise AuthenticodeVerificationError('The expected hash of the encryptedDigest does not match '
                                                        'countersigner\'s SignerInfo')

                cs_verification_context.timestamp = self.signer_info.countersigner.signing_time

                # We could be calling SignerInfo.verify or RFC3161SignedData.verify here, but those have identical
                # signatures. Note that RFC3161SignedData accepts a trusted_certificate_store argument, but we pass in
                # an explicit context anyway
                self.signer_info.countersigner.verify(cs_verification_context)
            except Exception:
                if allow_countersignature_errors:
                    pass
                else:
                    raise AuthenticodeVerificationError("An error occurred while validating the countersignature.")
            else:
                # If no errors occur, we should be fine setting the timestamp to the countersignature's timestamp
                verification_context.timestamp = self.signer_info.countersigner.signing_time

        self.signer_info.verify(verification_context)


class RFC3161SignerInfo(SignerInfo):
    """Subclass of SignerInfo that is used to contain the signerinfo for the RFC3161SignedData option."""

    _expected_content_type = rfc3161.TSTInfo
    _required_authenticated_attributes = (rfc2315.ContentType, rfc2315.Digest)
    _countersigner_class = None  # prevent countersigners in here


class RFC3161SignedData(SignedData):
    _expected_content_type = rfc3161.TSTInfo
    _signerinfo_class = RFC3161SignerInfo

    def __init__(self, data):
        """Some samples have shown to include a RFC-3161 countersignature in the unauthenticated attributes
        (as OID 1.3.6.1.4.1.311.3.3.1, which is in the Microsoft private namespace). This attribute contains its own
        signed data structure.

        :param asn1.pkcs7.SignedData data: The ASN.1 structure of the SignedData object
        """
        super().__init__(data)

    def _parse(self):
        super()._parse()

        # Get the tst_info
        self.tst_info = guarded_der_decode(self.data['encapContentInfo']['eContent'], asn1_spec=rfc3161.TSTInfo())

        if self.tst_info['version'] != 1:
            raise AuthenticodeParseError("TSTInfo.version must be 1, not %d" % self.data['version'])

        self.policy = self.tst_info['policy']  # TODO
        self.hash_algorithm = _get_digest_algorithm(self.tst_info['messageImprint']['hashAlgorithm'],
                                                    location="TSTInfo.messageImprint.hashAlgorithm")
        self.message_digest = bytes(self.tst_info['messageImprint']['hashedMessage'])
        self.serial_number = self.tst_info['serialNumber']
        self.signing_time = self.tst_info['genTime'].asDateTime
        self.signing_time_accuracy = accuracy_to_python(self.tst_info['accuracy'])
        # TODO handle case where directoryName is not a rdnSequence
        self.signing_authority = CertificateName(self.tst_info['tsa']['directoryName']['rdnSequence'])

        # signerInfos
        if len(self.signer_infos) != 1:
            raise AuthenticodeParseError("RFC3161 SignedData.signerInfos must contain exactly 1 signer, not %d" %
                                         len(self.signer_infos))

        self.signer_info = self.signer_infos[0]

    def check_message_digest(self, data):
        """Given the data, returns whether the hash_algorithm and message_digest match the data provided."""

        auth_attr_hash = self.hash_algorithm(data).digest()
        return auth_attr_hash == self.message_digest

    def verify(self, context=None, trusted_certificate_store=TRUSTED_CERTIFICATE_STORE):
        """Verifies the RFC3161 SignedData object. The context that is passed in must account for the certificate
        store of this object, or be left None.
        """

        # We should ensure that the hash in the SignerInfo matches the hash of the content
        # This is similar to the normal verification process, where the SpcInfo is verified
        # Note that the mapping between the RFC3161 SignedData object is ensured by the verifier in SignedData
        blob_hash = self.digest_algorithm(bytes(self.data['encapContentInfo']['eContent'])).digest()
        if blob_hash != self.signer_info.message_digest:
            raise AuthenticodeVerificationError('The expected hash of the TstInfo does not match SignerInfo')

        if context is None:
            context = VerificationContext(trusted_certificate_store, self.certificates,
                                          extended_key_usages=['time_stamping'])

        # The context is set correctly by the 'verify' function, including the current certificate store
        self.signer_info.verify(context)


if __name__ == "__main__":
    print("This is a list of all certificates in the Authenticode trust store, ordered by expiration date")
    for i, certificate in enumerate(sorted(TRUSTED_CERTIFICATE_STORE, key=lambda x: x.valid_to), start=1):
        print(i, certificate.valid_to, certificate)
