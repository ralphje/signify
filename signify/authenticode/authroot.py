from __future__ import annotations

import datetime
import hashlib
import pathlib
from collections.abc import Iterable
from typing import Any, cast

import mscerts
from asn1crypto import cms
from typing_extensions import Self

from signify import asn1
from signify._typing import HashFunction
from signify.asn1.hashing import _get_digest_algorithm
from signify.exceptions import (
    CertificateTrustListParseError,
    CTLCertificateVerificationError,
)
from signify.pkcs7 import signeddata
from signify.x509 import certificates, context

AUTHROOTSTL_PATH = pathlib.Path(mscerts.where(stl=True))


class CertificateTrustList(signeddata.SignedData):
    """A subclass of :class:`signify.pkcs7.SignedData`, containing a list of trusted
    root certificates. It is based on the following ASN.1 structure::

        CertificateTrustList ::= SEQUENCE {
          version CTLVersion DEFAULT v1,
          subjectUsage SubjectUsage,
          listIdentifier ListIdentifier OPTIONAL,
          sequenceNumber HUGEINTEGER OPTIONAL,
          ctlThisUpdate ChoiceOfTime,
          ctlNextUpdate ChoiceOfTime OPTIONAL,
          subjectAlgorithm AlgorithmIdentifier,
          trustedSubjects TrustedSubjects OPTIONAL,
          ctlExtensions [0] EXPLICIT Extensions OPTIONAL
        }
        CTLVersion ::= INTEGER {v1(0)}
        SubjectUsage ::= EnhancedKeyUsage
        ListIdentifier ::= OCTETSTRING
        TrustedSubjects ::= SEQUENCE OF TrustedSubject
        TrustedSubject ::= SEQUENCE{
          subjectIdentifier SubjectIdentifier,
          subjectAttributes Attributes OPTIONAL
        }
        SubjectIdentifier ::= OCTETSTRING

    .. warning::

       The CTL itself is currently not verifiable.

    """

    _expected_content_type = "microsoft_ctl"
    content_asn1: asn1.ctl.CertificateTrustList

    @property
    def subject_usage(self) -> list[str]:
        """Defines the EKU of the Certificate Trust List.
        Should be 1.3.6.1.4.1.311.20.1.
        """
        return cast(list[str], self.content_asn1["subject_usage"].native)

    @property
    def list_identifier(self) -> bytes | None:
        """The name of the template of the list."""
        return cast("bytes | None", self.content_asn1["list_identifier"].native)

    @property
    def sequence_number(self) -> int:
        """The unique number of this list"""
        return cast(int, self.content_asn1["sequence_number"].native)

    @property
    def this_update(self) -> datetime.datetime | None:
        """The date of the current CTL."""
        return cast(
            "datetime.datetime | None", self.content_asn1["ctl_this_update"].native
        )

    @property
    def next_update(self) -> datetime.datetime | None:
        """The date of the next CTL."""
        return cast(
            "datetime.datetime | None", self.content_asn1["ctl_next_update"].native
        )

    @property
    def subject_algorithm(self) -> HashFunction:
        """Digest algorithm of verifying the list."""
        return _get_digest_algorithm(
            self.content_asn1["subject_algorithm"],
            location="CertificateTrustList.subjectAlgorithm",
        )

    @property
    def _subjects(self) -> dict[str, CertificateTrustSubject]:
        return {
            subj.identifier.hex().lower(): subj
            for subj in (
                CertificateTrustSubject(subject)
                for subject in self.content_asn1["trusted_subjects"]
            )
        }

    # TODO: extensions??

    @property
    def subjects(self) -> Iterable[CertificateTrustSubject]:
        """A list of :class:`CertificateTrustSubject` s in this list."""

        return self._subjects.values()

    def verify_trust(
        self, chain: list[certificates.Certificate], *args: Any, **kwargs: Any
    ) -> bool:
        """Checks whether the specified certificate is valid in the given conditions
        according to this Certificate Trust List.

        :param List[Certificate] chain: The certificate chain to verify
        """

        # Find the subject belonging to this certificate
        subject = self.find_subject(chain[0])
        if not subject:
            raise CTLCertificateVerificationError(
                f"The root {chain[0]} is not in the certificate trust list"
            )
        return subject.verify_trust(chain, *args, **kwargs)

    def find_subject(
        self, certificate: certificates.Certificate
    ) -> CertificateTrustSubject | None:
        """Finds the :class:`CertificateTrustSubject` belonging to the provided
        :class:`signify.x509.Certificate`.

        :param signify.x509.Certificate certificate: The certificate to look for.
        :rtype: CertificateTrustSubject
        """

        if self.subject_algorithm == hashlib.sha1:
            identifier = certificate.sha1_fingerprint
        elif self.subject_algorithm == hashlib.sha256:
            identifier = certificate.sha256_fingerprint
        else:
            raise CertificateTrustListParseError(
                "The specified subject algorithm is not yet supported."
            )

        return self._subjects.get(identifier)

    @classmethod
    def from_stl_file(cls, path: pathlib.Path = AUTHROOTSTL_PATH) -> Self:
        """Loads a :class:`CertificateTrustList` from a specified path."""

        with path.open("rb") as f:
            data = cms.ContentInfo.load(f.read())

        if data["content_type"].native != "signed_data":
            raise CertificateTrustListParseError(
                "ContentInfo does not contain SignedData"
            )

        signed_data = cls(data["content"])
        return signed_data


class CertificateTrustSubject:
    """A subject listed in a :class:`CertificateTrustList`. The structure in this object
    has mostly been reverse-engineered using Windows tooling such as ``certutil -dump``.
    We do not pretend to have a complete picture of all the edge-cases that are
    considered.

    .. warning::

       The interpretation of the various attributes and their implications has been
       reverse-engineered. Though we seem to have a fairly solid understanding, various
       edge-cases may not have been considered.

    """

    def __init__(self, asn1: asn1.ctl.TrustedSubject):
        self.asn1 = asn1

    @property
    def identifier(self) -> bytes:
        return cast(bytes, self.asn1["subject_identifier"].native)

    @property
    def attributes(self) -> dict[str, Any]:
        """A dictionary mapping of attribute types to values."""
        return {
            attr["type"].native: attr["values"].native[0]
            for attr in self.asn1["subject_attributes"]
        }

    @property
    def extended_key_usages(self) -> list[str] | None:
        """Defines the EKU's the certificate is valid for. It may be empty, which we
        take as 'all is acceptable'.
        """
        return cast(
            "list[str] | None", self.attributes.get("microsoft_ctl_enhkey_usage", None)
        )

    @property
    def friendly_name(self) -> str | None:
        """The friendly name of the certificate."""
        return cast(
            "str | None", self.attributes.get("microsoft_ctl_friendly_name", None)
        )

    @property
    def key_identifier(self) -> bytes:
        """The sha1 fingerprint of the certificate."""
        return cast(bytes, self.attributes.get("microsoft_ctl_key_identifier", b""))

    @property
    def subject_name_md5(self) -> bytes:
        """The md5 of the subject name."""
        return cast(
            bytes, self.attributes.get("microsoft_ctl_subject_name_md5_hash", b"")
        )

    # TODO: RootProgramCertPolicies not implemented

    @property
    def auth_root_sha256(self) -> bytes:
        """The sha256 fingerprint of the certificate."""
        return cast(
            bytes, self.attributes.get("microsoft_ctl_auth_root_sha256_hash", b"")
        )

    @property
    def disallowed_filetime(self) -> datetime.datetime | None:
        """The time since when a certificate has been disabled. Digital signatures with
        a timestamp prior to this date continue to be valid, but use cases after this
        date are prohibited. It may be used in conjunction with
        :attr:`disallowed_extended_key_usages` to define specific EKU's to be disabled.
        """
        return cast(
            "datetime.datetime | None",
            self.attributes.get("microsoft_ctl_disallowed_filetime", None),
        )

    @property
    def root_program_chain_policies(self) -> list[str] | None:
        """A list of EKU's probably used for EV certificates."""
        return cast(
            "list[str] | None",
            self.attributes.get("microsoft_ctl_root_program_chain_policies", None),
        )

    @property
    def disallowed_extended_key_usages(self) -> list[str] | None:
        """Defines the EKU's the certificate is not valid for. When used in combination
        with :attr:`disallowed_filetime`, the disabled EKU's are only disabled from
        that date onwards, otherwise, it means since the beginning of time.
        """
        return cast(
            "list[str] | None",
            self.attributes.get("microsoft_ctl_disallowed_enhkey_usage", None),
        )

    @property
    def not_before_filetime(self) -> datetime.datetime | None:
        """The time since when new certificates from this CA are not trusted.
        Certificates from prior the date will continue to validate. When used in
        conjunction with :attr:`not_before_extended_key_usages`, this only concerns
        certificates issued after this date for the defined EKU's.
        """
        return cast(
            "datetime.datetime | None",
            self.attributes.get("microsoft_ctl_not_before_filetime", None),
        )

    @property
    def not_before_extended_key_usages(self) -> list[str] | None:
        """Defines the EKU's for which the :attr:`not_before_filetime` is considered. If
        that attribute is not defined, we assume that it means since the beginning of
        time.
        """
        return cast(
            "list[str] | None",
            self.attributes.get("microsoft_ctl_not_before_enhkey_usage", None),
        )

    def verify_trust(
        self,
        chain: list[certificates.Certificate],
        context: context.VerificationContext,
    ) -> bool:
        """Checks whether the specified certificate is valid in the given conditions
        according to this Certificate Trust List.

        :param List[Certificate] chain: The certificate chain to verify.
        :param VerificationContext context: The context to verify with. Mainly the
            timestamp and extended_key_usages are used.
        """

        timestamp = context.timestamp
        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc)
        extended_key_usages = context.extended_key_usages
        if extended_key_usages is None:
            extended_key_usages = ()

        # Start by converting the list of provided extended_key_usages to a list of OIDs
        requested_extended_key_usages = set(extended_key_usages)

        # Now check each of the properties
        if self.extended_key_usages and (
            requested_extended_key_usages - set(self.extended_key_usages)
        ):
            raise CTLCertificateVerificationError(
                f"The root {self.friendly_name} lists its extended key usages, but"
                f" {requested_extended_key_usages - set(self.extended_key_usages)} are"
                " not present"
            )

        # The notBefore time does concern the validity of the certificate that is being
        # validated. It must have a notBefore of before the timestamp
        if self.not_before_filetime is not None:
            to_verify_timestamp = chain[-1].valid_from

            if to_verify_timestamp >= self.not_before_filetime:
                # If there is a notBefore time, and there is no NotBeforeEnhkeyUsage,
                # then the validity concerns the entire certificate.
                if self.not_before_extended_key_usages is None:
                    raise CTLCertificateVerificationError(
                        f"The root {self.friendly_name} is disallowed for certificate"
                        f" issued after {self.not_before_filetime} (certificate is"
                        f" {to_verify_timestamp})"
                    )
                elif any(
                    eku in self.not_before_extended_key_usages
                    for eku in requested_extended_key_usages
                ):
                    raise CTLCertificateVerificationError(
                        f"The root {self.friendly_name} disallows requested EKU's"
                        f" {requested_extended_key_usages} to certificates issued after"
                        f" {self.not_before_filetime} (certificate is"
                        f" {to_verify_timestamp})"
                    )
        elif self.not_before_extended_key_usages is not None and any(
            eku in self.not_before_extended_key_usages
            for eku in requested_extended_key_usages
        ):
            raise CTLCertificateVerificationError(
                f"The root {self.friendly_name} disallows requested EKU's"
                f" {requested_extended_key_usages}"
            )

        # The DisallowedFiletime time does concern the timestamp of the signature
        # being verified.
        if self.disallowed_filetime is not None:
            if timestamp >= self.disallowed_filetime:
                # If there is a DisallowedFiletime, and there is no
                # DisallowedEnhkeyUsage, then the validity concerns the entire
                # certificate.
                if self.disallowed_extended_key_usages is None:
                    raise CTLCertificateVerificationError(
                        f"The root {self.friendly_name} is disallowed since "
                        f"{self.disallowed_filetime} (requested {timestamp})"
                    )
                elif any(
                    eku in self.disallowed_extended_key_usages
                    for eku in requested_extended_key_usages
                ):
                    raise CTLCertificateVerificationError(
                        f"The root {self.friendly_name} is disallowed for EKU's"
                        f" {self.disallowed_extended_key_usages} since"
                        f" {self.disallowed_filetime} (requested"
                        f" {requested_extended_key_usages} at {timestamp})"
                    )
        elif self.disallowed_extended_key_usages is not None and any(
            eku in self.disallowed_extended_key_usages
            for eku in requested_extended_key_usages
        ):
            raise CTLCertificateVerificationError(
                f"The root {self.friendly_name} disallows requested EKU's"
                f" {requested_extended_key_usages}"
            )

        return True
