import hashlib
import logging

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder

from . import asn1
from ._legacy import rsa_public_decrypt
from .exceptions import CertificateVerificationError, VerificationError

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
    def cryptography_x509(self):
        """Retrieves the :mod:`cryptography` x509 object."""

        if self._cryptography_x509 is None:
            self._cryptography_x509 = x509.load_der_x509_certificate(der_encoder.encode(self.data), default_backend())
        return self._cryptography_x509

    @property
    def openssl_x509(self):
        """Retrieves the :mod:`openssl` x509 object, or None if pyOpenSSL is not installed."""
        try:
            from OpenSSL import crypto
            return crypto.X509.from_cryptography(self.cryptography_x509)
        except ImportError:
            return None

    @classmethod
    def from_pem(cls, content):
        """Reads a Certificate from a PEM formatted file.

        :param content: The PEM-encoded certificate
        :return: A Certificate object.
        """
        x590_cert = x509.load_pem_x509_certificate(content, default_backend())
        cert = Certificate(der_decoder.decode(x590_cert.tbs_certificate_bytes,
                                              asn1Spec=asn1.x509.TBSCertificate())[0])
        cert._cryptography_x509 = x590_cert
        return cert

    def _verify_certificate(self, context):
        """Verifies some basic properties of the certificate, including:

        * Its validity period
        * Its ExtendedKeyUsage if required by the context.
        """
        if not self.valid_from <= context.timestamp <= self.valid_to:
            raise CertificateVerificationError("Certificate {cert} is outside its validity period. It is valid from "
                                               "{valid_from} to {valid_to}, but we checked it against {timestamp}"
                                               .format(cert=self, timestamp=context.timestamp,
                                                       valid_from=self.valid_from, valid_to=self.valid_to))

        # Verify extendedKeyUsage
        try:
            extended_key_usage = self.cryptography_x509.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            pass
        else:
            extended_key_usage_ = list(map(lambda x: tuple(map(int, x.dotted_string.split("."))), extended_key_usage))

            if context.extended_key_usage is not None and \
                    x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in extended_key_usage and \
                    context.extended_key_usage not in extended_key_usage_:
                raise CertificateVerificationError("Certificate %s does not have %s in its extendedKeyUsage" %
                                                   (self, context.extended_key_usage))

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

    def _legacy_verify_issuer(self, issuer, timestamp=None):
        """Given an issuer, falls back to using pyOpenSSL to verify the signature.

        :param Certificate issuer: The issuer to verify against
        :raises AuthenticodeVerificationError: if the verification was performed and unsuccessful
        :return: True if the verification was performed and succeeded, False if it was not performed
        """
        try:
            from OpenSSL import crypto
        except ImportError:
            logger.debug("pyopenssl is not installed, legacy verification not available.")
            return False

        store = crypto.X509Store()
        store.add_cert(issuer.openssl_x509)
        if timestamp is not None:
            store.set_time(timestamp)
        context = crypto.X509StoreContext(store, self.openssl_x509)
        try:
            context.verify_certificate()
        except crypto.X509StoreContextError as e:
            raise CertificateVerificationError("Failed verifying the certificate using the legacy method: %s" % e)

        return True

    def _verify_issuer(self, issuer, context, depth=0):
        """Verifies whether the provided issuer is a valid issuer for the current certificate.

        The following checks are performed:

        * If BasicConstraints is present, whether the CA attribute is present
        * If KeyUsage is present, whether the Certificate Signing key usage is allowed
        * Verifies the issuing certificate using :meth:`_verify_certificate`, e.g. on its ExtendedKeyUsage and validity
        * Verifies the public key against the signature in the certificate

        The latter is normally performed using cryptography, but if an old hashing algorithm is used, pyOpenSSL is used
        instead, if this is available and allowed by the context.

        :param Certificate issuer: the issuer to verify
        :param VerificationContext context: Used for some parameters, such as the timestamp.
        :param int depth: The current verification depth, used to check the BasicConstraints
        :raises AuthenticodeVerificationError: when this is not a valid issuer
        """

        issuer._verify_certificate(context)

        # Verify BasicConstraints
        try:
            basic_constraints = issuer.cryptography_x509.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            if issuer.version <= 2:
                logger.warning("Certificate %s does not have the BasicConstraints extension" % issuer)
            else:
                raise CertificateVerificationError("Certificate %s does not have the BasicConstraints extension" %
                                                    issuer)
        else:
            if not basic_constraints.ca:
                raise CertificateVerificationError("Certificate %s does not have CA in its BasicConstraints" % issuer)
            if basic_constraints.path_length is not None and basic_constraints.path_length < depth:
                raise CertificateVerificationError("Certificate %s is at depth %d, whereas its maximum is %s" %
                                                    (self, depth, basic_constraints.path_length))

        # Verify KeyUsage
        try:
            key_usage = issuer.cryptography_x509.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            if issuer.version <= 2 or context.is_trusted(issuer):
                logger.warning("Certificate %s does not have the KeyUsage extension" % issuer)
            else:
                raise CertificateVerificationError("Certificate %s does not have the KeyUsage extension" % issuer)
        else:
            if not key_usage.key_cert_sign:
                raise CertificateVerificationError("Certificate %s does not have keyCertSign set in its KeyUsage" %
                                                   issuer)

        # Verify the signature
        try:
            issuer.verify_signature(self.cryptography_x509.signature, self.cryptography_x509.tbs_certificate_bytes,
                                    self.cryptography_x509.signature_hash_algorithm)
        except UnsupportedAlgorithm:
            logger.info("The hashing algorithm is not supported by the cryptography module. "
                        "Trying pyopenssl instead")
            if not context.allow_legacy:
                raise CertificateVerificationError("The signature algorithm of {} is unsupported by cryptography, and "
                                                   "legacy checking is disallowed.")
            elif not self._legacy_verify_issuer(issuer, context.timestamp):
                raise CertificateVerificationError("The signature algorithm of {} is unsupported by cryptography and "
                                                   "pyOpenSSL is not installed.")

        return True

    def _build_chain(self, context, depth=0):
        """Given a context, builds a chain up to a trusted certificate. This is a generator function, generating all
        valid chains.

        This method is called recursively and calls :meth:`_verify_issuer` on all possible issuers of this certificate.
        If the parent certificate is a valid issuer, it gets the same treatment. The method :meth:`_verify_issuer` may
        raise an error. This error is silently swallowed when another issuer is valid. Otherwise, this error is passed
        down.

        This method will stop calling itself when a trust anchor is found according to the context. This method will
        also stop when some depth is reached, or the candidate parent is already in the chain.

        .. warning::
           No error is raised when :meth:`_verify_issuer` never fails, but no chain is found either. This may happen
           when somewhere in the chain, no valid parent was found. Always check whether this method returns a chain.

        :param VerificationContext context: The context for building the chain. Most importantly, contains
            all certificates to build the chain from, but also their properties are relevant.
        :param depth: The depth of the chain building. Used for recursive calling of this method, and should be set to
            0 for all other uses of this method.
        :return: Iterable of all of the valid chains from this certificate up to and including a trusted anchor.
            Note that this may be an empty iteration if no candidate parent certificate was found.
        :rtype: Iterable[Iterable[Certificate]]
        :raises AuthenticodeVerificationError: When somewhere up the chain an error occurs; this may happen when a
            candidate parent certificate does not pass verification. If an error is raised, it will be that of the
            first parent certificate that was attempted, or anywhere up its chain. If any other valid chain was found,
            the error for that first invalid candidate parent is silently swallowed. Note that all of this does not
            happen when no candidate parent certificate was found (anywhere up the chain); in that case this iterator
            simply yields nothing.
        """
        # when we are too deep and have not found any trusted root, we just bail out (not yielding anything)
        if depth > 10:
            return
        # when this certificate is trusted, we found a trust anchor.
        if context.is_trusted(self):
            yield [self]
            return

        # first_error is raised when the loop iteration fails, and no other iteration succeeds
        # first_error is None: no iteration has been performed
        # first_error is False: at least one iteration has succeeded
        first_error = None
        for issuer in context.find_certificates(subject=self.issuer):
            try:
                # prevent looping on itself for self-signed certificates
                if issuer == self:
                    continue

                # _verify_issuer may raise an error when the issuer is not valid for this certificate
                self._verify_issuer(issuer, context, depth)

                # _build_chain may raise an error when the issuer can't find its issuer
                for chain in issuer._build_chain(context, depth + 1):
                    yield [self] + chain

            except VerificationError as e:
                # if first_error is None, this is the first run.
                if first_error is None:
                    first_error = e
                continue

            else:
                # the iteration succeeded once, so we don't bother raising errors from the other iterations anymore
                first_error = False

        if first_error:
            raise first_error

    def verify(self, context):
        """Verifies the certificate, and its chain.

        :param VerificationContext context: The context for verifying the certificate.
        :return: A list of valid certificate chains for this certificate.
        :rtype: Iterable[Iterable[Certificate]]
        :raises AuthenticodeVerificationError: When the certificate could not be verified.
        """

        self._verify_certificate(context)
        chains = list(self._build_chain(context))

        if not chains:
            raise CertificateVerificationError("No valid certificate chain found to a trust anchor from {}"
                                               .format(self))

        return chains
