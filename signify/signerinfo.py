import hashlib

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
from pyasn1_modules import rfc5652, rfc2315

from signify.asn1 import guarded_ber_decode, pkcs7
from signify.exceptions import VerificationError, SignerInfoParseError, \
    SignerInfoVerificationError, ParseError
from . import asn1, _print_type
from .asn1.helpers import time_to_python
from .certificates import CertificateName

ACCEPTED_DIGEST_ALGORITHMS = (hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha384, hashlib.sha512)


def _verify_empty_algorithm_parameters(algorithm, location):
    if 'parameters' in algorithm and algorithm['parameters'].isValue:
        parameters = guarded_ber_decode(algorithm['parameters'])
        if not isinstance(parameters, univ.Null):
            raise ParseError("%s has parameters set, which is unexpected" % (location,))


def _get_digest_algorithm(algorithm, location, acceptable=ACCEPTED_DIGEST_ALGORITHMS):
    result = asn1.oids.get(algorithm['algorithm'])
    if result not in acceptable:
        raise ParseError("%s must be one of %s, not %s" % (location, [x().name for x in acceptable],
                                                           _print_type(result)))

    _verify_empty_algorithm_parameters(algorithm, location)
    return result


def _get_encryption_algorithm(algorithm, location):
    result = asn1.oids.OID_TO_PUBKEY.get(algorithm['algorithm'])
    if result is None:
        raise ParseError("%s: %s is not acceptable as encryption algorithm" % (location, algorithm['algorithm']))

    _verify_empty_algorithm_parameters(algorithm, location)
    return result


class SignerInfo(object):
    _countersigner_class = "CounterSignerInfo"
    _required_authenticated_attributes = (rfc2315.ContentType, rfc2315.Digest)
    _expected_content_type = None

    def __init__(self, data):
        """The Authenticode's SignerInfo structure.

        :param data: The ASN.1 structure of the SignerInfo.
        """
        if isinstance(self._countersigner_class, str):
            self._countersigner_class = globals()[self._countersigner_class]

        self.data = data
        self._parse()

    def _parse(self):
        if self.data['version'] != 1:
            raise SignerInfoParseError("SignerInfo.version must be 1, not %d" % self.data['version'])

        # We can handle several different rfc types here
        if isinstance(self.data, rfc2315.SignerInfo):
            self.issuer = CertificateName(self.data['issuerAndSerialNumber']['issuer'][0])
            self.serial_number = self.data['issuerAndSerialNumber']['serialNumber']

            self.authenticated_attributes = self._parse_attributes(
                self.data['authenticatedAttributes'],
                required=self._required_authenticated_attributes
            )
            self._encoded_authenticated_attributes = self._encode_attributes(self.data['authenticatedAttributes'])

            self.unauthenticated_attributes = self._parse_attributes(self.data['unauthenticatedAttributes'])

            self.digest_encryption_algorithm = _get_encryption_algorithm(self.data['digestEncryptionAlgorithm'],
                                                                         location="SignerInfo.digestEncryptionAlgorithm")
            self.encrypted_digest = bytes(self.data['encryptedDigest'])

        elif isinstance(self.data, rfc5652.SignerInfo):
            # TODO: handle case where sid contains key identifier
            self.issuer = CertificateName(self.data['sid']['issuerAndSerialNumber']['issuer'][0])
            self.serial_number = self.data['sid']['issuerAndSerialNumber']['serialNumber']

            self.authenticated_attributes = self._parse_attributes(
                self.data['signedAttrs'],
                required=self._required_authenticated_attributes
            )
            self._encoded_authenticated_attributes = self._encode_attributes(self.data['signedAttrs'])

            self.unauthenticated_attributes = self._parse_attributes(self.data['unsignedAttrs'])

            self.digest_encryption_algorithm = _get_encryption_algorithm(self.data['signatureAlgorithm'],
                                                                         location="SignerInfo.signatureAlgorithm")
            self.encrypted_digest = bytes(self.data['signature'])

        else:
            raise SignerInfoParseError("Unknown SignerInfo type %s" % type(self.data))

        self.digest_algorithm = _get_digest_algorithm(self.data['digestAlgorithm'],
                                                      location="SignerInfo.digestAlgorithm")

        # Parse the content of the authenticated attributes
        # - The messageDigest
        self.message_digest = None
        if rfc2315.Digest in self.authenticated_attributes:
            if len(self.authenticated_attributes[rfc2315.Digest]) != 1:
                raise SignerInfoParseError("Only one Digest expected in SignerInfo.authenticatedAttributes")

            self.message_digest = bytes(self.authenticated_attributes[rfc2315.Digest][0])

        # - The contentType
        self.content_type = None
        if rfc2315.ContentType in self.authenticated_attributes:
            if len(self.authenticated_attributes[rfc2315.ContentType]) != 1:
                raise SignerInfoParseError("Only one ContentType expected in SignerInfo.authenticatedAttributes")

            self.content_type = asn1.oids.get(self.authenticated_attributes[rfc2315.ContentType][0])

            if self._expected_content_type is not None and self.content_type is not self._expected_content_type:
                raise SignerInfoParseError("Unexpected content type for SignerInfo, expected %s, got %s" %
                                            (_print_type(self._expected_content_type),
                                             _print_type(self.content_type)))

        # - The signingTime (used by countersigner)
        self.signing_time = None
        if rfc5652.SigningTime in self.authenticated_attributes:
            if len(self.authenticated_attributes[rfc5652.SigningTime]) != 1:
                raise SignerInfoParseError("Only one SigningTime expected in SignerInfo.authenticatedAttributes")

            self.signing_time = time_to_python(self.authenticated_attributes[rfc5652.SigningTime][0])

        # - The countersigner
        self.countersigner = None
        if pkcs7.Countersignature in self.unauthenticated_attributes:
            if len(self.unauthenticated_attributes[pkcs7.Countersignature]) != 1:
                raise SignerInfoParseError("Only one CountersignInfo expected in SignerInfo.unauthenticatedAttributes")

            self.countersigner = self._countersigner_class(self.unauthenticated_attributes[pkcs7.Countersignature][0])

    def check_message_digest(self, data):
        """Given the data, returns whether the hash_algorithm and message_digest match the data provided."""

        auth_attr_hash = self.digest_algorithm(data).digest()
        return auth_attr_hash == self.message_digest

    @classmethod
    def _parse_attributes(cls, data, required=()):
        """Given a set of Attributes, parses them and returns them as a dict

        :param data: The authenticatedAttributes or unauthenticatedAttributes to process
        :param required: A list of required attributes
        """

        if isinstance(data, rfc2315.Attributes):
            type_key, value_key = 'type', 'values'
        elif isinstance(data, (rfc5652.SignedAttributes, rfc5652.UnsignedAttributes)):
            type_key, value_key = 'attrType', 'attrValues'

        result = {}
        for attr in data:
            typ = asn1.oids.get(attr[type_key])
            values = []
            for value in attr[value_key]:
                if not isinstance(typ, tuple):
                    value = guarded_ber_decode(value, asn1_spec=typ())
                values.append(value)
            result[typ] = values

        if not all((x in result for x in required)):
            raise SignerInfoParseError("Not all required attributes found. Required: %s; Found: %s" %
                                       ([_print_type(x) for x in required], [_print_type(x) for x in result]))

        return result

    @classmethod
    def _encode_attributes(cls, data):
        """Given a set of Attributes, sorts them in the correct order. They need to be sorted in ascending order in the
        SET, when DER encoded. This also makes sure that the tag on Attributes is correct.

        :param data: The authenticatedAttributes or unauthenticatedAttributes to encode
        """
        sorted_data = sorted([der_encoder.encode(i) for i in data])
        new_attrs = rfc2315.Attributes()
        for i, attribute in enumerate(sorted_data):
            d, _ = ber_decoder.decode(attribute, asn1Spec=rfc2315.Attribute())
            new_attrs.setComponentByPosition(i, d)
        return der_encoder.encode(new_attrs)

    def _verify_issuer(self, issuer, context):
        """Verifies whether the given issuer is valid for the given context. Similar to
        :meth:`Certificate._verify_issuer`. Does not support legacy verification method.

        :param Certificate issuer: The Certificate to verify
        :param VerificationContext context: The
        """

        issuer.verify(context)

        try:
            issuer.verify_signature(self.encrypted_digest,
                                    self._encoded_authenticated_attributes,
                                    self.digest_algorithm,
                                    allow_legacy=context.allow_legacy)
        except VerificationError as e:
            raise SignerInfoVerificationError("Could not verify {cert} as the signer of the authenticated "
                                              "attributes in {cls}: {exc}"
                                              .format(cert=issuer, cls=type(self).__name__, exc=e))

    def _build_chain(self, context):
        """Given a context, builds a chain up to a trusted certificate. This is a generator function, generating all
        valid chains.

        This method will call :meth:`VerificationContext.verify` for all possible candidates.

        :param VerificationContext context: The context for building the chain. Most importantly, contains
            all certificates to build the chain from, but also their properties are relevant.
        :return: Iterable of all of the valid chains from this SignedInfo up to and including a trusted anchor.
            Note that this may be an empty iteration if no candidate parent certificate was found.
        :rtype: Iterable[Iterable[Certificate]]
        :raises AuthenticodeVerificationError: When :meth:`_verify_issuer` fails or any of the underlying calls to
            :meth:`VerificationContext.verify` fails. See the semantics of :meth:`VerificationContext.verify` for when
            that may happen. If any error occurs, it is silently swallowed unless no valid chain is found. In that case
            the first error that occurred is raised. If no error occurs, no error is raised.
        """

        # this loop was designed in the same way that Certificate._build_chain was built
        # first_error is None until the first iteration. When it becomes False, we do not need to raise anything.
        first_error = None
        for issuer in context.find_certificates(issuer=self.issuer, serial_number=self.serial_number):
            try:
                # _verify_issuer may fail when it is not a valid issuer for this SignedInfo
                self._verify_issuer(issuer, context)

                # _build_chain may fail when anywhere up its chain an error occurs
                yield context.verify(issuer)
            except VerificationError as e:
                if first_error is None:
                    first_error = e
            else:
                first_error = False

        if first_error:
            raise first_error

    def verify(self, context):
        """Verifies the SignerInfo, and its chain.

        :param VerificationContext context: The context for verifying the SignerInfo.
        :return: A list of valid certificate chains for this SignerInfo.
        :rtype: Iterable[Iterable[Certificate]]
        :raises AuthenticodeVerificationError: When the SignerInfo could not be verified.
        """

        chains = list(self._build_chain(context))

        if not chains:
            raise SignerInfoVerificationError("No valid certificate chain found to a trust anchor from {}"
                                              .format(type(self).__name__))

        return chains

    def potential_chains(self, context):
        """Retrieves all potential chains from this SignerInfo instance.

        :param VerificationContext context: The context
        :return: A list of potential certificate chains for this SignerInfo.
        :rtype: Iterable[Iterable[Certificate]]
        """

        for certificate in context.find_certificates(issuer=self.issuer, serial_number=self.serial_number):
            yield from context.potential_chains(certificate)


class CounterSignerInfo(SignerInfo):
    _required_authenticated_attributes = (rfc2315.ContentType, rfc5652.SigningTime, rfc2315.Digest)
