from __future__ import annotations

import datetime
from typing import Any, Iterable, cast

from asn1crypto import cms
from asn1crypto.core import Asn1Value
from typing_extensions import Literal

from signify._typing import HashFunction
from signify.asn1.hashing import _get_digest_algorithm
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
    authenticated_attributes: dict[str, list[Any]]
    unauthenticated_attributes: dict[str, list[Any]]
    digest_encryption_algorithm: str
    encrypted_digest: bytes
    digest_algorithm: HashFunction
    message_digest: bytes | None
    content_type: str | None
    signing_time: datetime.datetime | None
    countersigner: CounterSignerInfo | None

    _countersigner_class: type[CounterSignerInfo] | str | None = "CounterSignerInfo"
    _required_authenticated_attributes: Iterable[str] = (
        "content_type",
        "message_digest",
    )
    _expected_content_type: str | None = None

    def __init__(
        self, data: cms.SignerInfo, parent: signeddata.SignedData | None = None
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
        if self.data["sid"].name == "subject_key_identifier":
            raise SignerInfoParseError(
                "Cannot handle SignerInfo.sid with a subject_key_identifier"
            )

        self.issuer = CertificateName(self.data["sid"].chosen["issuer"])
        self.serial_number = self.data["sid"].chosen["serial_number"].native
        self.authenticated_attributes = self._parse_attributes(
            self.data["signed_attrs"],
            required=self._required_authenticated_attributes,
        )
        self._encoded_authenticated_attributes = self._encode_attributes(
            self.data["signed_attrs"]
        )
        self.unauthenticated_attributes = self._parse_attributes(
            self.data["unsigned_attrs"]
        )
        self.digest_encryption_algorithm = self.data["signature_algorithm"][
            "algorithm"
        ].native
        self.encrypted_digest = self.data["signature"].native
        self.digest_algorithm = _get_digest_algorithm(
            self.data["digest_algorithm"], location="SignerInfo.digestAlgorithm"
        )

        # Parse the content of the authenticated attributes
        # - The messageDigest
        self.message_digest = None
        if "message_digest" in self.authenticated_attributes:
            if len(self.authenticated_attributes["message_digest"]) != 1:
                raise SignerInfoParseError(
                    "Only one Digest expected in SignerInfo.authenticatedAttributes"
                )

            self.message_digest = self.authenticated_attributes["message_digest"][
                0
            ].native

        # - The contentType
        self.content_type = None
        if "content_type" in self.authenticated_attributes:
            if len(self.authenticated_attributes["content_type"]) != 1:
                raise SignerInfoParseError(
                    "Only one ContentType expected in"
                    " SignerInfo.authenticatedAttributes"
                )

            self.content_type = self.authenticated_attributes["content_type"][0].native

            if (
                self._expected_content_type is not None
                and self.content_type != self._expected_content_type
            ):
                raise SignerInfoParseError(
                    "Unexpected content type for SignerInfo, expected"
                    f" {self._expected_content_type}, got"
                    f" {self.content_type}"
                )

        # - The signingTime (used by countersigner)
        self.signing_time = None
        if "signing_time" in self.authenticated_attributes:
            if len(self.authenticated_attributes["signing_time"]) != 1:
                raise SignerInfoParseError(
                    "Only one SigningTime expected in"
                    " SignerInfo.authenticatedAttributes"
                )

            self.signing_time = self.authenticated_attributes["signing_time"][0].native

        # - The countersigner
        self.countersigner = None
        if "counter_signature" in self.unauthenticated_attributes:
            if len(self.unauthenticated_attributes["counter_signature"]) != 1:
                raise SignerInfoParseError(
                    "Only one CountersignInfo expected in"
                    " SignerInfo.unauthenticatedAttributes"
                )

            assert self._countersigner_class is not None and not isinstance(
                self._countersigner_class, str
            )  # typing
            self.countersigner = self._countersigner_class(
                self.unauthenticated_attributes["counter_signature"][0]
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
        cls, data: cms.CMSAttributes, required: Iterable[str] = ()
    ) -> dict[str, list[Asn1Value]]:
        """Given a set of Attributes, parses them and returns them as a dict

        :param data: The authenticatedAttributes or unauthenticatedAttributes to process
        :param required: A list of required attributes
        """

        result = {attr["type"].native: list(attr["values"]) for attr in data}

        if not all(x in result for x in required):
            raise SignerInfoParseError(
                "Not all required attributes found."
                f" Required: {required};"
                f" Found: {result}"
            )

        return result

    @classmethod
    def _encode_attributes(cls, data: cms.CMSAttributes) -> bytes:
        """Given a set of Attributes, prepares them for creating a digest. It as per
        RFC 5652 section 5.2, this changes the tag from implicit to explicit.

        :param data: The attributes to encode
        """

        new_attrs = type(data)(contents=data.contents)
        return cast(bytes, new_attrs.dump())

    def _verify_issuer_signature(
        self, issuer: Certificate, context: VerificationContext
    ) -> None:
        """Check the issuer signature against the information in the class. Use
        :meth:`_verify_issuer` for full verification.

        :param Certificate issuer: The Certificate to verify
        :param VerificationContext context: The context for verification
        :raises SignerInfoVerificationError: If the issuer signature is invalid
        """

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

    def _verify_issuer(
        self,
        issuer: Certificate,
        context: VerificationContext,
        signing_time: datetime.datetime | None = None,
    ) -> list[Certificate]:
        """Verifies whether the given issuer is valid for this :class:`SignerInfo`,
        and valid in the given context. Similar to :meth:`Certificate._verify_issuer`.

        It adds the ``signing_time`` to the context if necessary.
        """

        # _verify_issuer_signature may fail when it is not a valid issuer for
        # this SignedInfo
        self._verify_issuer_signature(issuer, context)

        if signing_time is not None:
            context.timestamp = signing_time
        return context.verify(issuer)

    def _build_chain(
        self,
        context: VerificationContext,
        signing_time: datetime.datetime | None = None,
    ) -> Iterable[list[Certificate]]:
        """Given a context, builds a chain up to a trusted certificate. This is a
        generator function, generating all valid chains.

        This method will call :meth:`VerificationContext.verify` for all possible
        candidates.

        :param VerificationContext context: The context for building the chain. Most
            importantly, contains all certificates to build the chain from, but also
            their properties are relevant.
        :param signing_time: The time to be used as timestamp when creating the chain
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
                # may fail when anywhere up its chain an error occurs
                yield self._verify_issuer(issuer, context, signing_time)
            except VerificationError as e:  # noqa: PERF203
                if first_error is None:
                    first_error = e
            else:
                first_error = False

        if first_error:
            raise first_error

    def verify(
        self,
        context: VerificationContext,
        signing_time: datetime.datetime | None = None,
    ) -> Iterable[list[Certificate]]:
        """Verifies that this :class:`SignerInfo` verifies up to a chain with the root
        of a trusted certificate.

        :param VerificationContext context: The context for verifying the SignerInfo.
        :param signing_time: The time to be used as timestamp when creating the chain
        :return: A list of valid certificate chains for this SignerInfo.
        :rtype: Iterable[Iterable[Certificate]]
        :raises AuthenticodeVerificationError: When the SignerInfo could not be
            verified.
        """

        chains = list(self._build_chain(context, signing_time))

        if not chains:
            raise SignerInfoVerificationError(
                "No valid certificate chain found to a trust anchor from"
                f" {type(self).__name__}"
            )

        return chains

    def potential_chains(
        self, context: VerificationContext
    ) -> Iterable[list[Certificate]]:
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
        "content_type",
        "signing_time",
        "message_digest",
    )
