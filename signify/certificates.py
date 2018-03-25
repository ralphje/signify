import hashlib
import logging

import asn1crypto.pem
import asn1crypto.x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder

from . import asn1
from ._legacy import rsa_public_decrypt
from .exceptions import CertificateVerificationError

logger = logging.getLogger(__name__)


def _from_hashlib_to_crypto(algorithm):
    return {
        hashlib.md5: hashes.MD5(),
        hashlib.sha1: hashes.SHA1(),
        hashlib.sha224: hashes.SHA224(),
        hashlib.sha256: hashes.SHA256(),
        hashlib.sha384: hashes.SHA384(),
        hashlib.sha512: hashes.SHA512(),
    }.get(algorithm, algorithm)


class Certificate(object):
    def __init__(self, data):
        """Representation of a Certificate. It is built from an ASN.1 structure.

        :type data: asn1.pkcs7.ExtendedCertificateOrCertificate or asn1.x509.Certificate or asn1.x509.TBSCertificate
        :param data: The ASN.1 structure
        """

        self.data = data
        self._cryptography_x509 = None
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

    @property
    def _der_bytes(self):
        return der_encoder.encode(self.data)

    @property
    def cryptography_x509(self):
        """Retrieves the :mod:`cryptography` x509 object."""

        if self._cryptography_x509 is None:
            self._cryptography_x509 = x509.load_der_x509_certificate(self._der_bytes, default_backend())
        return self._cryptography_x509

    @property
    def asn1crypto_certificate(self):
        return asn1crypto.x509.Certificate.load(self._der_bytes)

    @classmethod
    def from_der(cls, content):
        return cls(der_decoder.decode(content, asn1Spec=asn1.x509.Certificate())[0])

    @classmethod
    def from_pem(cls, content):
        """Reads a Certificate from a PEM formatted file.

        :param content: The PEM-encoded certificate
        :return: A Certificate object.
        """
        type_name, headers, der_bytes = asn1crypto.pem.unarmor(content)
        return cls.from_der(der_bytes)

    def _legacy_verify_signature(self, signature, data, algorithm):
        """Performs a legacy signature verification. This method is intended for the case where the encryptedDigest
        does not contain an ASN.1 structure, but a raw hash value instead.

        This case is described in more detail on
        https://mta.openssl.org/pipermail/openssl-users/2015-September/002053.html

        As there is no module in Python that allows us to do this (M2Crypto is not Python 3 compatible at this time),
        we use direct calls to the CFFI module of OpenSSL. That ugly *barf* is put in _legacy.

        The arguments are identical to those of :meth:`verify_signature`.
        """

        public_key = self.cryptography_x509.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            logger.info("Legacy signature verification only allowed for RSA public keys.")
            return False

        crypto_algorithm = _from_hashlib_to_crypto(algorithm)
        expected_hash = rsa_public_decrypt(public_key, signature, padding.PKCS1v15(), crypto_algorithm)

        if isinstance(crypto_algorithm, hashes.MD5):
            hash_algorithm = hashlib.md5
        elif isinstance(crypto_algorithm, hashes.SHA1):
            hash_algorithm = hashlib.sha1
        else:
            logger.info("Legacy signature verification only allowed for MD5 and SHA1 signatures.")
            return False

        actual_hash = hash_algorithm(data).digest()
        if expected_hash != actual_hash:
            raise CertificateVerificationError("Invalid legacy RSA signature for %s" % self)

        return True

    def verify_signature(self, signature, data, algorithm):
        """Verifies whether the signature bytes match the data using the hashing algorithm. Supports RSA and EC keys.
        Note that not all hashing algorithms are supported by the cryptography module.

        :param bytes signature: The signature to verify
        :param bytes data: The data that must be verified
        :type algorithm: cryptography.hazmat.primitives.hashes.HashAlgorithm or hashlib.function
        :param algorithm: The hashing algorithm to use
        """

        # Given a hashlib.sha1 object, convert it to the appropritate value
        crypto_algorithm = _from_hashlib_to_crypto(algorithm)
        public_key = self.cryptography_x509.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            try:
                public_key.verify(signature, data, padding.PKCS1v15(), crypto_algorithm)
            except InvalidSignature:
                raise CertificateVerificationError("Invalid RSA signature for %s" % self)

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            try:
                public_key.verify(signature, data, ec.ECDSA(crypto_algorithm))
            except InvalidSignature:
                raise CertificateVerificationError("Invalid EC signature for %s" % self)
        else:
            raise CertificateVerificationError("Unknown public key type for certificate %s" % self)

    def verify(self, context):
        """Verifies the certificate, and its chain.

        :param VerificationContext context: The context for verifying the certificate.
        :return: A list of valid certificate chains for this certificate.
        :rtype: Iterable[Certificate]
        :raises AuthenticodeVerificationError: When the certificate could not be verified.
        """

        return context.verify(self)
