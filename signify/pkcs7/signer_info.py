from __future__ import annotations

import datetime
from collections.abc import Iterable
from typing import cast

from asn1crypto import cms
from asn1crypto.core import Asn1Value
from typing_extensions import Literal

from signify._typing import HashFunction
from signify.asn1.hashing import _get_digest_algorithm
from signify.exceptions import (
    CounterSignerError,
    SignerInfoParseError,
    SignerInfoVerificationError,
    VerificationError,
)
from signify.pkcs7 import signed_data
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

    The most important part of this structure are the authenticated attributes. These
    will at least contain the hash of the content of the :class:`SignedData` structure.
    We can verify this hash by hashing the same content using the hash in
    :attr:`digest_algorithm`

    The :attr:`encrypted_digest` contains a signature by the issuer over these
    authenticated attributes (the authenticated attributes are hashed and verified
    using the :attr:`digest_encryption_algorithm`). The :attr:`issuer` and
    :attr:`serial_number` contains a reference to the certificate of the issuer, that
    is used for this signature.

    This class defines how a certain signer, (identified by their :attr:`issuer`)

    .. attribute:: asn1

       The underlying ASN.1 data object

    .. attribute:: parent

       The parent :class:`SignedData` object (or if other SignerInfos are present, it
       may be another object)

    """

    _countersigner_class: type[CounterSignerInfo] | str | None = "CounterSignerInfo"
    _required_authenticated_attributes: Iterable[str] = (
        "content_type",
        "message_digest",
    )
    _singular_authenticated_attributes: Iterable[str] = (
        "message_digest",
        "content_type",
        "signing_time",
    )
    _singular_unauthenticated_attributes: Iterable[str] = ("counter_signature",)
    _expected_content_type: str | None = None

    def __init__(
        self, asn1: cms.SignerInfo, parent: signed_data.SignedData | None = None
    ):
        """
        :param asn1: The ASN.1 structure of the SignerInfo.
        :param parent: The parent :class:`SignedData` object.
        """
        if isinstance(self._countersigner_class, str):
            self._countersigner_class = globals()[self._countersigner_class]

        self.asn1 = asn1
        self.parent = parent
        self._validate_asn1()

    def _validate_asn1(self) -> None:
        if self.asn1["sid"].name == "subject_key_identifier":
            raise SignerInfoParseError(
                "Cannot handle SignerInfo.sid with a subject_key_identifier"
            )

        # Check if all required attributes are defined.
        if not all(
            x in self.authenticated_attributes
            for x in self._required_authenticated_attributes
        ):
            raise SignerInfoParseError(
                "Not all required attributes found."
                f" Required: {self._required_authenticated_attributes};"
                f" Found: {self.authenticated_attributes}"
            )

        # Check that any defined singular authenticated attribute, is only present
        # once.
        for attribute in self._singular_authenticated_attributes:
            if attribute in self.authenticated_attributes:
                if len(self.authenticated_attributes[attribute]) != 1:
                    raise SignerInfoParseError(
                        f"Only one {attribute} expected in"
                        f" SignerInfo.authenticatedAttributes, found"
                        f" {len(self.authenticated_attributes[attribute])}"
                    )

        # Check that any defined singular unauthenticated attribute, is only present
        # once.
        for attribute in self._singular_unauthenticated_attributes:
            if attribute in self.unauthenticated_attributes:
                if len(self.unauthenticated_attributes[attribute]) != 1:
                    raise SignerInfoParseError(
                        f"Only one {attribute} expected in"
                        f" SignerInfo.unauthenticatedAttributes, found"
                        f" {len(self.unauthenticated_attributes[attribute])}"
                    )

        # Verify the content type against the expected content type
        if (
            "content_type" in self.authenticated_attributes
            and self._expected_content_type is not None
            and self.content_type != self._expected_content_type
        ):
            raise SignerInfoParseError(
                "Unexpected content type for SignerInfo, expected"
                f" {self._expected_content_type}, got"
                f" {self.content_type}"
            )

    @property
    def issuer(self) -> CertificateName:
        """The issuer of the SignerInfo, i.e. the certificate of the signer of the
        SignedData object.
        """
        return CertificateName(self.asn1["sid"].chosen["issuer"])

    @property
    def serial_number(self) -> int:
        """The serial number as specified by the issuer."""
        return cast(int, self.asn1["sid"].chosen["serial_number"].native)

    @classmethod
    def _parse_attributes(cls, data: cms.CMSAttributes) -> dict[str, list[Asn1Value]]:
        """Given a set of Attributes, parses them and returns them as a dict

        :param data: The authenticatedAttributes or unauthenticatedAttributes to process
        """
        return {attr["type"].native: list(attr["values"]) for attr in data}

    @property
    def authenticated_attributes(self) -> dict[str, list[Asn1Value]]:
        """A SignerInfo object can contain both signed and unsigned attributes. These
        contain additional information about the signature, but also the content type
        and message digest. The difference between signed and unsigned is that unsigned
        attributes are not validated.

        The type of this attribute is a dictionary. You should not need to access this
        value directly, rather using one of the attributes listed below.
        """
        return self._parse_attributes(self.asn1["signed_attrs"])

    @classmethod
    def _encode_attributes(cls, data: cms.CMSAttributes) -> bytes:
        """Given a set of Attributes, prepares them for creating a digest. It as per
        RFC 5652 section 5.2, this changes the tag from implicit to explicit.

        :param data: The attributes to encode
        """

        new_attrs = type(data)(contents=data.contents)
        return cast(bytes, new_attrs.dump())

    @property
    def _encoded_authenticated_attributes(self) -> bytes:
        return self._encode_attributes(self.asn1["signed_attrs"])

    @property
    def unauthenticated_attributes(self) -> dict[str, list[Asn1Value]]:
        """A SignerInfo object can contain both signed and unsigned attributes. These
        contain additional information about the signature, but also the content type
        and message digest. The difference between signed and unsigned is that unsigned
        attributes are not validated.

        The type of this attribute is a dictionary. You should not need to access this
        value directly, rather using one of the attributes listed below.
        """
        return self._parse_attributes(self.asn1["unsigned_attrs"])

    @property
    def digest_encryption_algorithm(self) -> str:
        """This is the algorithm used for signing the digest with the signer's key."""
        return cast(str, self.asn1["signature_algorithm"]["algorithm"].native)

    @property
    def encrypted_digest(self) -> bytes:
        """The result of encrypting the message digest and associated information with
        the signer's private key.
        """
        return cast(bytes, self.asn1["signature"].native)

    @property
    def digest_algorithm(self) -> HashFunction:
        """The digest algorithm, i.e. the hash algorithm, under which the content and
        the authenticated attributes are signed.
        """
        return _get_digest_algorithm(
            self.asn1["digest_algorithm"], location="SignerInfo.digestAlgorithm"
        )

    ### parsed attributes
    @property
    def message_digest(self) -> bytes | None:
        """This is an authenticated attribute, containing the signed digest of
        the data.
        """
        if "message_digest" in self.authenticated_attributes:
            return cast(
                bytes, self.authenticated_attributes["message_digest"][0].native
            )
        return None

    @property
    def content_type(self) -> str | None:
        """This is an authenticated attribute, containing the content type of the
        content being signed.
        """
        if "content_type" in self.authenticated_attributes:
            return cast(str, self.authenticated_attributes["content_type"][0].native)
        return None

    @property
    def signing_time(self) -> datetime.datetime | None:
        """This is an authenticated attribute, containing the timestamp of signing. Note
        that this should only be present in countersigner objects.
        """
        if "signing_time" in self.authenticated_attributes:
            return cast(
                datetime.datetime,
                self.authenticated_attributes["signing_time"][0].native,
            )
        return None

    @property
    def countersigner(self) -> CounterSignerInfo | None:
        """This is an unauthenticated attribute, containing the countersigner of the
        SignerInfo.
        """
        if "counter_signature" in self.unauthenticated_attributes:
            assert self._countersigner_class is not None and not isinstance(
                self._countersigner_class, str
            )  # typing
            return self._countersigner_class(
                cast(
                    cms.SignerInfo,
                    self.unauthenticated_attributes["counter_signature"][0],
                )
            )
        return None

    def check_message_digest(self, data: bytes) -> bool:
        """Given the data, returns whether the hash_algorithm and message_digest match
        the data provided.
        """

        auth_attr_hash = self.digest_algorithm()
        auth_attr_hash.update(data)
        return auth_attr_hash.digest() == self.message_digest

    def _verify_issuer_signature(
        self, issuer: Certificate, context: VerificationContext
    ) -> None:
        """Check the issuer signature against the information in the class. Use
        :meth:`_verify_issuer` for full verification.

        :param issuer: The Certificate to verify
        :param context: The context for verification
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

    def _verify_countersigner(
        self,
        context: VerificationContext,
        countersignature_mode: Literal["strict", "permit", "ignore"] = "strict",
    ) -> datetime.datetime | None:
        """Verifies the countersigner of the SignerInfo, if available.

        Returns the verified signing time of the binary, if correct, or returns None.
        """

        if self.countersigner is None or countersignature_mode == "ignore":
            return None

        try:
            # 3. Check the countersigner hash.
            # Make sure to use the same digest_algorithm that the countersigner used
            if not self.countersigner.check_message_digest(self.encrypted_digest):
                raise CounterSignerError(
                    "The expected hash of the encryptedDigest does not match"
                    " countersigner's SignerInfo"
                )

            context.timestamp = self.countersigner.signing_time

            # We could be calling SignerInfo.verify or RFC3161SignedData.verify
            # here, but those have identical signatures. Note that
            # RFC3161SignedData accepts a trusted_certificate_store argument, but
            # we pass in an explicit context anyway
            self.countersigner.verify(context)
        except Exception as e:
            if countersignature_mode != "strict":
                pass
            else:
                raise CounterSignerError(
                    f"An error occurred while validating the countersignature: {e}"
                )
        else:
            # If no errors occur, we should be fine setting the timestamp to the
            # countersignature's timestamp
            return self.countersigner.signing_time

        return None

    def _build_chain(
        self,
        context: VerificationContext,
        signing_time: datetime.datetime | None = None,
    ) -> Iterable[list[Certificate]]:
        """Given a context, builds a chain up to a trusted certificate. This is a
        generator function, generating all valid chains.

        This method will call :meth:`VerificationContext.verify` for all possible
        candidates.

        :param context: The context for building the chain. Most importantly, contains
            all certificates to build the chain from, but also their properties are
            relevant.
        :param signing_time: The time to be used as timestamp when creating the chain
        :return: Iterable of all of the valid chains from this SignedInfo up to and
            including a trusted anchor. Note that this may be an empty iteration if no
            candidate parent certificate was found.
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
        *,
        countersigner_context: VerificationContext | None = None,
        countersignature_mode: Literal["strict", "permit", "ignore"] = "strict",
    ) -> Iterable[list[Certificate]]:
        """Verifies that this :class:`SignerInfo` verifies up to a chain with the root
        of a trusted certificate.

        :param context: The context for verifying the SignerInfo.
        :param countersigner_context: The VerificationContext for verifying the chain
            of the :class:`CounterSignerInfo`.
        :param countersignature_mode: Changes how countersignatures are handled.
            Defaults to ``strict``, which means that errors in the countersignature
            result in verification failure.

            If set to ``permit``, the countersignature is checked, but when it errors,
            it is verified as if the countersignature was never set.

            When set to ``ignore``, countersignatures are never checked.
        :return: A list of valid certificate chains for this SignerInfo.
        :raises AuthenticodeVerificationError: When the SignerInfo could not be
            verified.
        """

        signing_time = None
        if countersigner_context and countersignature_mode != "ignore":
            signing_time = self._verify_countersigner(
                countersigner_context, countersignature_mode
            )

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
        """

        for certificate in context.find_certificates(
            issuer=self.issuer, serial_number=self.serial_number
        ):
            yield from context.potential_chains(certificate)


class CounterSignerInfo(SignerInfo):
    """A counter-signer provides information about when a :class:`SignerInfo` was
    signed. It basically acts as the SignerInfo of the SignerInfo, linking the
    message digest to the original SignerInfo's encrypted_digest.

    This normally works by sending the digest of the SignerInfo to an external
    trusted service, that will include a signed time in its response.
    """

    _required_authenticated_attributes = (
        "content_type",
        "signing_time",
        "message_digest",
    )
