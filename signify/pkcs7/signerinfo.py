from __future__ import annotations

import datetime
from typing import Any, Iterable, cast

from pyasn1.type import univ
from pyasn1.type.base import Asn1Type
from pyasn1_modules import rfc2315, rfc5652
from typing_extensions import Literal

from signify import _print_type, asn1
from signify._typing import HashFunction, OidTuple
from signify.asn1 import guarded_ber_decode, pkcs7
from signify.asn1 import preserving_der as preserving_der_encoder
from signify.asn1.hashing import _get_digest_algorithm, _get_encryption_algorithm
from signify.asn1.helpers import time_to_python
from signify.exceptions import (
    SignerInfoParseError,
    SignerInfoVerificationError,
    VerificationError,
)
from signify.pkcs7 import signeddata
from signify.x509 import VerificationContext
from signify.x509.certificates import Certificate, CertificateName


class SignerInfo:
    """The SignerInfo class is defined in RFC2315 and RFC5652 (amongst others) and
    defines the per-signer information in a :class:`SignedData` structure.

    It is based on the following ASN.1 object (as per RFC2315)::

        SignerInfo ::= SEQUENCE {
          version Version,
          issuerAndSerialNumber IssuerAndSerialNumber,
          digestAlgorithm DigestAlgorithmIdentifier,
          authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
          digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
          encryptedDigest EncryptedDigest,
          unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
        }

    This class supports RFC2315 and RFC5652.

    .. attribute:: data

       The underlying ASN.1 data object

    .. attribute:: parent

       The parent :class:`SignedData` object (or if other SignerInfos are present, it
       may be another object)

    .. attribute:: issuer
       :type: CertificateName

       The issuer of the SignerInfo, i.e. the certificate of the signer of the
       SignedData object.

    .. attribute:: serial_number

       The serial number as specified by the issuer.

    .. attribute:: digest_algorithm

       The digest algorithm, i.e. the hash algorithm, under which the content and the
       authenticated attributes are
       signed.

    .. attribute:: authenticated_attributes
                   unauthenticated_attributes

       A SignerInfo object can contain both signed and unsigned attributes. These
       contain additional information about the signature, but also the content type
       and message digest. The difference between signed and unsigned is that unsigned
       attributes are not validated.

       The type of this attribute is a dictionary. You should not need to access this
       value directly, rather using one of the attributes listed below.

    .. attribute:: digest_encryption_algorithm

       This is the algorithm used for signing the digest with the signer's key.

    .. attribute:: encrypted_digest

       The result of encrypting the message digest and associated information with the
       signer's private key.


    The following attributes are automatically parsed and added to the list of
    attributes if present.

    .. attribute:: message_digest

       This is an authenticated attribute, containing the signed digest of the data.

    .. attribute:: content_type

       This is an authenticated attribute, containing the content type of the content
       being signed.

    .. attribute:: signing_time

       This is an authenticated attribute, containing the timestamp of signing. Note
       that this should only be present in countersigner objects.

    .. attribute:: countersigner

       This is an unauthenticated attribute, containing the countersigner of the
       SignerInfo.

    """

    issuer: CertificateName
    serial_number: int
    authenticated_attributes: dict[OidTuple | type[Asn1Type], list[Any]]
    unauthenticated_attributes: dict[OidTuple | type[Asn1Type], list[Any]]
    digest_encryption_algorithm: str
    encrypted_digest: bytes
    digest_algorithm: HashFunction
    message_digest: bytes | None
    content_type: OidTuple | type[Asn1Type] | None
    signing_time: datetime.datetime | None
    countersigner: CounterSignerInfo | None

    _countersigner_class: type[CounterSignerInfo] | str | None = "CounterSignerInfo"
    _required_authenticated_attributes: Iterable[univ.ObjectIdentifier] = (
        rfc2315.ContentType,
        rfc2315.Digest,
    )
    _expected_content_type: type[univ.Sequence] | None = None

    def __init__(
        self,
        data: rfc2315.SignerInfo | rfc5652.SignerInfo,
        parent: signeddata.SignedData | None = None,
    ):
        """
        :param data: The ASN.1 structure of the SignerInfo.
        :param parent: The parent :class:`SignedData` object.
        """
        if isinstance(self._countersigner_class, str):
            self._countersigner_class = globals()[self._countersigner_class]

        self.data = data
        self.parent = parent
        self._parse()

    def _parse(self) -> None:
        if self.data["version"] != 1:
            raise SignerInfoParseError(
                "SignerInfo.version must be 1, not %d" % self.data["version"]
            )

        # We can handle several different rfc types here
        if isinstance(self.data, rfc2315.SignerInfo):
            self.issuer = CertificateName(
                self.data["issuerAndSerialNumber"]["issuer"][0]
            )
            self.serial_number = self.data["issuerAndSerialNumber"]["serialNumber"]

            self.authenticated_attributes = self._parse_attributes(
                self.data["authenticatedAttributes"],
                required=self._required_authenticated_attributes,
            )
            self._encoded_authenticated_attributes = self._encode_attributes(
                self.data["authenticatedAttributes"]
            )

            self.unauthenticated_attributes = self._parse_attributes(
                self.data["unauthenticatedAttributes"]
            )

            self.digest_encryption_algorithm = _get_encryption_algorithm(
                self.data["digestEncryptionAlgorithm"],
                location="SignerInfo.digestEncryptionAlgorithm",
            )
            self.encrypted_digest = bytes(self.data["encryptedDigest"])

        elif isinstance(self.data, rfc5652.SignerInfo):
            # TODO: handle case where sid contains key identifier
            self.issuer = CertificateName(
                self.data["sid"]["issuerAndSerialNumber"]["issuer"][0]
            )
            self.serial_number = self.data["sid"]["issuerAndSerialNumber"][
                "serialNumber"
            ]

            self.authenticated_attributes = self._parse_attributes(
                self.data["signedAttrs"],
                required=self._required_authenticated_attributes,
            )
            self._encoded_authenticated_attributes = self._encode_attributes(
                self.data["signedAttrs"]
            )

            self.unauthenticated_attributes = self._parse_attributes(
                self.data["unsignedAttrs"]
            )

            self.digest_encryption_algorithm = _get_encryption_algorithm(
                self.data["signatureAlgorithm"],
                location="SignerInfo.signatureAlgorithm",
            )
            self.encrypted_digest = bytes(self.data["signature"])

        else:
            raise SignerInfoParseError("Unknown SignerInfo type %s" % type(self.data))

        self.digest_algorithm = _get_digest_algorithm(
            self.data["digestAlgorithm"], location="SignerInfo.digestAlgorithm"
        )

        # Parse the content of the authenticated attributes
        # - The messageDigest
        self.message_digest = None
        if rfc2315.Digest in self.authenticated_attributes:
            if len(self.authenticated_attributes[rfc2315.Digest]) != 1:
                raise SignerInfoParseError(
                    "Only one Digest expected in SignerInfo.authenticatedAttributes"
                )

            self.message_digest = bytes(
                self.authenticated_attributes[rfc2315.Digest][0]
            )

        # - The contentType
        self.content_type = None
        if rfc2315.ContentType in self.authenticated_attributes:
            if len(self.authenticated_attributes[rfc2315.ContentType]) != 1:
                raise SignerInfoParseError(
                    "Only one ContentType expected in"
                    " SignerInfo.authenticatedAttributes"
                )

            self.content_type = asn1.oids.get(
                self.authenticated_attributes[rfc2315.ContentType][0]
            )

            if (
                self._expected_content_type is not None
                and self.content_type is not self._expected_content_type
            ):
                raise SignerInfoParseError(
                    "Unexpected content type for SignerInfo, expected"
                    f" {_print_type(self._expected_content_type)}, got"
                    f" {_print_type(self.content_type)}"
                )

        # - The signingTime (used by countersigner)
        self.signing_time = None
        if rfc5652.SigningTime in self.authenticated_attributes:
            if len(self.authenticated_attributes[rfc5652.SigningTime]) != 1:
                raise SignerInfoParseError(
                    "Only one SigningTime expected in"
                    " SignerInfo.authenticatedAttributes"
                )

            self.signing_time = time_to_python(
                self.authenticated_attributes[rfc5652.SigningTime][0]
            )

        # - The countersigner
        self.countersigner = None
        if pkcs7.Countersignature in self.unauthenticated_attributes:
            if len(self.unauthenticated_attributes[pkcs7.Countersignature]) != 1:
                raise SignerInfoParseError(
                    "Only one CountersignInfo expected in"
                    " SignerInfo.unauthenticatedAttributes"
                )

            assert self._countersigner_class is not None and not isinstance(
                self._countersigner_class, str
            )
            self.countersigner = self._countersigner_class(
                self.unauthenticated_attributes[pkcs7.Countersignature][0]
            )

    def check_message_digest(self, data: bytes) -> bool:
        """Given the data, returns whether the hash_algorithm and message_digest match
        the data provided.
        """

        auth_attr_hash = self.digest_algorithm()
        auth_attr_hash.update(data)
        return auth_attr_hash.digest() == self.message_digest

    @classmethod
    def _parse_attributes(
        cls,
        data: (
            rfc2315.Attributes | rfc5652.SignedAttributes | rfc5652.UnsignedAttributes
        ),
        required: Iterable[univ.ObjectIdentifier] = (),
    ) -> dict[OidTuple | type[Asn1Type], list[Any]]:
        """Given a set of Attributes, parses them and returns them as a dict

        :param data: The authenticatedAttributes or unauthenticatedAttributes to process
        :param required: A list of required attributes
        """

        if isinstance(data, rfc2315.Attributes):
            type_key, value_key = "type", "values"
        elif isinstance(data, (rfc5652.SignedAttributes, rfc5652.UnsignedAttributes)):
            type_key, value_key = "attrType", "attrValues"

        result: dict[tuple[int, ...] | type[Asn1Type], list[Any]] = {}
        for attr in data:
            typ = asn1.oids.get(attr[type_key], asn1.oids.OID_TO_CLASS)
            values = []
            for value in attr[value_key]:
                if not isinstance(typ, tuple):
                    value = guarded_ber_decode(value, asn1_spec=typ())
                values.append(value)
            result[typ] = values

        if not all(x in result for x in required):
            raise SignerInfoParseError(
                "Not all required attributes found."
                f" Required: {[_print_type(x) for x in required]};"
                f" Found: {[_print_type(x) for x in result]}"
            )

        return result

    @classmethod
    def _encode_attributes(
        cls,
        data: (
            rfc2315.Attributes | rfc5652.SignedAttributes | rfc5652.UnsignedAttributes
        ),
    ) -> bytes:
        """Given a set of Attributes, prepares them for creating a digest. It used to
        sort them by their DER encoded values, now it is mostly a method to preserve
        the exact order they where in when they were encoded.

        :param data: The authenticatedAttributes or unauthenticatedAttributes to encode
        """
        # sorting may not be necessary, as it is not in the spec
        new_attrs = type(data)()
        new_attrs.extend(data)
        return cast(bytes, preserving_der_encoder.encode(new_attrs))

    def _verify_issuer(self, issuer: Certificate, context: VerificationContext) -> None:
        """Verifies whether the given issuer is valid for the given context. Similar to
        :meth:`Certificate._verify_issuer`. Does not support legacy verification method.

        :param Certificate issuer: The Certificate to verify
        :param VerificationContext context: The
        """

        issuer.verify(context)

        try:
            issuer.verify_signature(
                self.encrypted_digest,
                self._encoded_authenticated_attributes,
                self.digest_algorithm,
                allow_legacy=context.allow_legacy,
            )
        except VerificationError as e:
            raise SignerInfoVerificationError(
                f"Could not verify {issuer} as the signer of the authenticated"
                f" attributes in {type(self).__name__}: {e}"
            )

    def _build_chain(
        self, context: VerificationContext
    ) -> Iterable[Iterable[Certificate]]:
        """Given a context, builds a chain up to a trusted certificate. This is a
        generator function, generating all valid chains.

        This method will call :meth:`VerificationContext.verify` for all possible
        candidates.

        :param VerificationContext context: The context for building the chain. Most
            importantly, contains all certificates to build the chain from, but also
            their properties are relevant.
        :return: Iterable of all of the valid chains from this SignedInfo up to and
            including a trusted anchor. Note that this may be an empty iteration if no
            candidate parent certificate was found.
        :rtype: Iterable[Iterable[Certificate]]
        :raises AuthenticodeVerificationError: When :meth:`_verify_issuer` fails or
            any of the underlying calls to :meth:`VerificationContext.verify` fails.
            See the semantics of :meth:`VerificationContext.verify` for when that may
            happen. If any error occurs, it is silently swallowed unless no valid chain
            is found. In that case the first error that occurred is raised. If no error
            occurs, no error is raised.
        """

        # this loop was designed in the same way that Certificate._build_chain was built
        # first_error is None until the first iteration. When it becomes False, we do
        # not need to raise anything.
        first_error: VerificationError | None | Literal[False] = None
        for issuer in context.find_certificates(
            issuer=self.issuer, serial_number=self.serial_number
        ):
            try:
                # _verify_issuer may fail when it is not a valid issuer for this
                # SignedInfo
                self._verify_issuer(issuer, context)

                # _build_chain may fail when anywhere up its chain an error occurs
                yield context.verify(issuer)
            except VerificationError as e:  # noqa: PERF203
                if first_error is None:
                    first_error = e
            else:
                first_error = False

        if first_error:
            raise first_error

    def verify(self, context: VerificationContext) -> Iterable[Iterable[Certificate]]:
        """Verifies that this :class:`SignerInfo` verifies up to a chain with the root
        of a trusted certificate.

        :param VerificationContext context: The context for verifying the SignerInfo.
        :return: A list of valid certificate chains for this SignerInfo.
        :rtype: Iterable[Iterable[Certificate]]
        :raises AuthenticodeVerificationError: When the SignerInfo could not be
            verified.
        """

        chains = list(self._build_chain(context))

        if not chains:
            raise SignerInfoVerificationError(
                "No valid certificate chain found to a trust anchor from"
                f" {type(self).__name__}"
            )

        return chains

    def potential_chains(
        self, context: VerificationContext
    ) -> Iterable[Iterable[Certificate]]:
        """Retrieves all potential chains from this SignerInfo instance.

        :param VerificationContext context: The context
        :return: A list of potential certificate chains for this SignerInfo.
        :rtype: Iterable[Iterable[Certificate]]
        """

        for certificate in context.find_certificates(
            issuer=self.issuer, serial_number=self.serial_number
        ):
            yield from context.potential_chains(certificate)


class CounterSignerInfo(SignerInfo):
    """The class CounterSignerInfo is a subclass of :class:`SignerInfo`. It is used as
    the SignerInfo of a SignerInfo, containing the timestamp the SignerInfo was created
    on. This normally works by sending the digest of the SignerInfo to an external
    trusted service, that will include a signed time in its response.
    """

    _required_authenticated_attributes = (
        rfc2315.ContentType,
        rfc5652.SigningTime,
        rfc2315.Digest,
    )
