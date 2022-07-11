import collections
import logging
import re

import asn1crypto.pem
import asn1crypto.x509
from oscrypto import asymmetric
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1_modules import rfc5652, rfc5280, rfc2315

from signify import asn1
from signify._compat import cached_property
from signify.asn1 import oids
from signify.asn1.helpers import time_to_python, bitstring_to_bytes
from signify.exceptions import CertificateVerificationError

logger = logging.getLogger(__name__)


AlgorithmIdentifier = collections.namedtuple('AlgorithmIdentifier', 'algorithm parameters')


class Certificate:
    """Representation of a Certificate. It is built from an ASN.1 structure.

    .. attribute:: data

       The underlying ASN.1 data object

    .. attribute:: signature_algorithm
                   signature_value
                   subject_public_algorithm
                   subject_public_key

       These values are considered part of the certificate, but not
       fully parsed.

    .. attribute:: version

       This is the version of the certificate

    .. attribute:: serial_number

       The full integer serial number of the certificate

    .. attribute:: issuer
                   subject

       The :class:`CertificateName` for the issuer and subject.

    .. attribute:: valid_from
                   valid_to

       The datetime objects between which the certificate is valid.

    .. attribute:: extensions

       This is a list of extension objects.
    """

    def __init__(self, data):
        """

        :type data: asn1.pkcs7.ExtendedCertificateOrCertificate or asn1.x509.Certificate or asn1.x509.TBSCertificate
        :param data: The ASN.1 structure
        """

        self.data = data
        self._parse()

    @classmethod
    def is_certificate(cls, data):
        if isinstance(data, rfc5652.CertificateChoices) and 'certificate' not in data:
            return False
        return True

    def _parse(self):
        if isinstance(self.data, rfc5652.CertificateChoices):
            if 'extendedCertificate' in self.data:
                raise NotImplementedError("Support for extendedCertificate is not implemented")
            if 'certificate' not in self.data:
                raise NotImplementedError("This is not a certificate, probably an attribute certificate "
                                          "(containing no public key)")

            certificate = self.data['certificate']
            self.signature_algorithm = certificate['signatureAlgorithm']
            self.signature_value = certificate['signatureValue'] \
                if 'signatureValue' in certificate else certificate['signature']
            tbs_certificate = certificate['tbsCertificate']

        elif isinstance(self.data, (rfc2315.ExtendedCertificateOrCertificate,
                                    rfc5652.ExtendedCertificateOrCertificate)):
            if 'extendedCertificate' in self.data:
                # TODO: Not sure if needed.
                raise NotImplementedError("Support for extendedCertificate is not implemented")

            certificate = self.data['certificate']
            self.signature_algorithm = certificate['signatureAlgorithm']
            self.signature_value = certificate['signatureValue'] \
                if 'signatureValue' in certificate else certificate['signature']
            tbs_certificate = certificate['tbsCertificate']

        elif isinstance(self.data, (rfc2315.Certificate, rfc5280.Certificate)):
            certificate = self.data
            self.signature_algorithm = certificate['signatureAlgorithm']
            self.signature_value = certificate['signatureValue'] \
                if 'signatureValue' in certificate else certificate['signature']
            tbs_certificate = certificate['tbsCertificate']

        else:
            tbs_certificate = self.data

        self.version = int(tbs_certificate['version']) + 1
        self.serial_number = int(tbs_certificate['serialNumber'])
        self.issuer = CertificateName(tbs_certificate['issuer'][0])
        self.valid_from = time_to_python(tbs_certificate['validity']['notBefore'])
        self.valid_to = time_to_python(tbs_certificate['validity']['notAfter'])
        self.subject = CertificateName(tbs_certificate['subject'][0])

        self.subject_public_algorithm = AlgorithmIdentifier(
            algorithm=tbs_certificate['subjectPublicKeyInfo']['algorithm']['algorithm'],
            parameters=bytes(tbs_certificate['subjectPublicKeyInfo']['algorithm']['parameters'])
        )
        self.subject_public_key = bitstring_to_bytes(tbs_certificate['subjectPublicKeyInfo']['subjectPublicKey'])

        self.extensions = {}
        if 'extensions' in tbs_certificate and tbs_certificate['extensions'].isValue:
            for extension in tbs_certificate['extensions']:
                self.extensions[asn1.oids.get(extension['extnID'])] = extension['extnValue']

    def __str__(self):
        return "{} (serial:{}, sha1:{})".format(self.subject.dn, self.serial_number, self.sha1_fingerprint)

    def __hash__(self):
        return hash((self.issuer, self.serial_number, self.subject,
                     self.subject_public_algorithm, self.subject_public_key))

    def __eq__(self, other):
        return isinstance(other, Certificate) and \
               self.issuer == other.issuer and \
               self.serial_number == other.serial_number and \
               self.subject == other.subject and \
               self.subject_public_algorithm == other.subject_public_algorithm and \
               self.subject_public_key == other.subject_public_key

    @classmethod
    def from_der(cls, content):
        """Load the Certificate object from DER-encoded data"""
        return cls(der_decoder.decode(content, asn1Spec=rfc5280.Certificate())[0])

    @classmethod
    def from_pem(cls, content):
        """Reads a Certificate from a PEM formatted file."""
        return next(cls.from_pems(content))

    @classmethod
    def from_pems(cls, content):
        """Reads a Certificate from a PEM formatted file."""
        for type_name, headers, der_bytes in asn1crypto.pem.unarmor(content, multiple=True):
            yield cls.from_der(der_bytes)

    @cached_property
    def to_der(self):
        """Returns the DER-encoded data from this certificate."""
        return der_encoder.encode(self.data)

    @cached_property
    def to_asn1crypto(self):
        """Retrieves the :mod:`asn1crypto` x509 Certificate object."""
        return asn1crypto.x509.Certificate.load(self.to_der)

    @cached_property
    def sha256_fingerprint(self):
        return self.to_asn1crypto.sha256_fingerprint.replace(" ", "").lower()

    @cached_property
    def sha1_fingerprint(self):
        return self.to_asn1crypto.sha1_fingerprint.replace(" ", "").lower()

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

    def potential_chains(self, context):
        """Alias for :meth:`VerificationContext.potential_chains`"""

        return context.potential_chains(self)

    def verify(self, context):
        """Alias for :meth:`VerificationContext.verify`"""

        return context.verify(self)


class CertificateName:
    def __init__(self, data):
        self.data = data

    def __eq__(self, other):
        return self.rdns == other.rdns

    def __hash__(self):
        return hash(self.rdns)

    def __str__(self):
        return self.dn

    @property
    def dn(self):
        """Returns an (almost) rfc2253 compatible string given a RDNSequence"""

        result = []
        for n in self.data[::-1]:
            type_value = n[0]  # get the AttributeTypeAndValue object

            #   If the AttributeType is in a published table of attribute types
            #   associated with LDAP [4], then the type name string from that table
            #   is used, otherwise it is encoded as the dotted-decimal encoding of
            #   the AttributeType's OBJECT IDENTIFIER.
            type = oids.OID_TO_RDN.get(type_value['type'], ".".join(map(str, type_value['type'])))
            value = str(ber_decoder.decode(type_value['value'])[0])

            # Escaping according to RFC2253
            value = re.sub("([,+\"<>;\\\\])", r"\\\1", value)
            if value.startswith("#"):
                value = "\\" + value
            if value.endswith(" "):
                value = value[:-1] + "\\ "
            result.append("{type}={value}".format(type=type, value=value))
        return ", ".join(result)

    @property
    def rdns(self):
        """A list of all components of the object."""
        return tuple(self.get_components())

    def get_components(self, component_type=None):
        """Get individual components of this CertificateName

        :param component_type: if provided, yields only values of this type,
            if not provided, yields tuples of (type, value)
        """

        for n in self.data[::-1]:
            type_value = n[0]  # get the AttributeTypeAndValue object
            type = oids.OID_TO_RDN.get(type_value['type'], ".".join(map(str, type_value['type'])))
            value = str(ber_decoder.decode(type_value['value'])[0])

            if component_type is not None:
                if component_type in (type_value['type'], ".".join(map(str, type_value['type'])), type):
                    yield value
            else:
                yield type, value
