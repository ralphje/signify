import logging

import asn1crypto.pem
import asn1crypto.x509
from oscrypto import asymmetric
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder

from . import asn1
from .exceptions import CertificateVerificationError

logger = logging.getLogger(__name__)


class Certificate(object):
    def __init__(self, data):
        """Representation of a Certificate. It is built from an ASN.1 structure.

        :type data: asn1.pkcs7.ExtendedCertificateOrCertificate or asn1.x509.Certificate or asn1.x509.TBSCertificate
        :param data: The ASN.1 structure
        """

        self.data = data
        self._parse()

    def _parse(self):
        if isinstance(self.data, asn1.pkcs7.ExtendedCertificateOrCertificate):
            if 'extendedCertificate' in self.data:
                # TODO: Not sure if needed.
                raise NotImplementedError("Support for extendedCertificate is not implemented")

            certificate = self.data['certificate']
            self.signature_algorithm = certificate['signatureAlgorithm']
            self.signature_value = certificate['signatureValue']
            tbs_certificate = certificate['tbsCertificate']

        elif isinstance(self.data, asn1.x509.Certificate):
            certificate = self.data
            self.signature_algorithm = certificate['signatureAlgorithm']
            self.signature_value = certificate['signatureValue']
            tbs_certificate = certificate['tbsCertificate']

        else:
            tbs_certificate = self.data

        self.version = int(tbs_certificate['version']) + 1
        self.serial_number = int(tbs_certificate['serialNumber'])
        self.issuer = tbs_certificate['issuer'][0]
        self.issuer_dn = tbs_certificate['issuer'][0].to_string()
        self.valid_from = tbs_certificate['validity']['notBefore'].to_python_time()
        self.valid_to = tbs_certificate['validity']['notAfter'].to_python_time()
        self.subject = tbs_certificate['subject'][0]
        self.subject_dn = tbs_certificate['subject'][0].to_string()

        self.subject_public_algorithm = tbs_certificate['subjectPublicKeyInfo']['algorithm']
        self.subject_public_key = tbs_certificate['subjectPublicKeyInfo']['subjectPublicKey']

        self.extensions = {}
        if 'extensions' in tbs_certificate and tbs_certificate['extensions'].isValue:
            for extension in tbs_certificate['extensions']:
                self.extensions[asn1.oids.get(extension['extnID'])] = extension['extnValue']

    def __str__(self):
        return "{}(serial:{})".format(self.subject_dn, self.serial_number)

    @classmethod
    def from_der(cls, content):
        """Load the Certificate object from DER-encoded data"""
        return cls(der_decoder.decode(content, asn1Spec=asn1.x509.Certificate())[0])

    @classmethod
    def from_pem(cls, content):
        """Reads a Certificate from a PEM formatted file."""
        type_name, headers, der_bytes = asn1crypto.pem.unarmor(content)
        return cls.from_der(der_bytes)

    @property
    def to_der(self):
        """Returns the DER-encoded data from this certificate."""
        return der_encoder.encode(self.data)

    @property
    def to_asn1crypto(self):
        """Retrieves the :mod:`asn1crypto` x509 Certificate object."""
        return asn1crypto.x509.Certificate.load(self.to_der)

    def verify_signature(self, signature, data, algorithm, allow_legacy=False):
        """Verifies whether the signature bytes match the data using the hashing algorithm. Supports RSA and EC keys.
        Note that not all hashing algorithms are supported.

        :param bytes signature: The signature to verify
        :param bytes data: The data that must be verified
        :type algorithm: a hashlib function
        :param algorithm: The hashing algorithm to use
        :param bool allow_legacy: If True, allows a legacy signature verification. This method is intended for the case
            where the encryptedDigest does not contain an ASN.1 structure, but a raw hash value instead. It is attempted
            automatically when verification of the RSA signature fails.

            This case is described in more detail on
            https://mta.openssl.org/pipermail/openssl-users/2015-September/002053.html
        """

        public_key = asymmetric.load_public_key(self.to_asn1crypto.public_key)
        if public_key.algorithm == 'rsa':
            verify_func = asymmetric.rsa_pkcs1v15_verify
        elif public_key.algorithm == 'dsa':
            verify_func = asymmetric.dsa_verify
        elif public_key.algorithm == 'ec':
            verify_func = asymmetric.ecdsa_verify
        else:
            raise CertificateVerificationError("Signature algorithm %s is unsupported for %s" %
                                               (public_key.algorithm, self))

        try:
            verify_func(public_key, signature, data, algorithm().name)
        except Exception as e:
            if not allow_legacy or public_key.algorithm != 'rsa':
                raise CertificateVerificationError("Invalid signature for %s: %s" % (self, e))
        else:
            return

        try:
            asymmetric.rsa_pkcs1v15_verify(public_key, signature, algorithm(data).digest(), 'raw')
        except Exception as e:
            raise CertificateVerificationError("Invalid signature for %s (legacy attempted): %s" % (self, e))

    def verify(self, context):
        """Alias for :meth:`VerificationContext.verify`"""

        return context.verify(self)
