from __future__ import annotations

import datetime
import hashlib
import pathlib
from typing import Any, Iterable

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

    .. attribute:: data

       The underlying ASN.1 data object

    .. attribute:: subject_usage

       Defines the EKU of the Certificate Trust List. Should be 1.3.6.1.4.1.311.20.1.

    .. attribute:: list_identifier

       The name of the template of the list.

    .. attribute:: sequence_number

       The unique number of this list

    .. attribute:: this_update

       The date of the current CTL.

    .. attribute:: next_update

       The date of the next CTL.

    .. attribute:: subject_algorithm

       Digest algorithm of verifying the list.

    .. warning::

       The CTL itself is currently not verifiable.

    """

    _expected_content_type = "microsoft_ctl"

    subject_usage: list[str]
    list_identifier: bytes | None
    sequence_number: int
    this_update: datetime.datetime | None
    next_update: datetime.datetime | None
    subject_algorithm: HashFunction

    def _parse(self) -> None:
        super()._parse()

        self.subject_usage = self.content["subject_usage"].native
        self.list_identifier = self.content["list_identifier"].native
        self.sequence_number = self.content["sequence_number"].native
        self.this_update = self.content["ctl_this_update"].native
        self.next_update = self.content["ctl_next_update"].native
        self.subject_algorithm = _get_digest_algorithm(
            self.content["subject_algorithm"],
            location="CertificateTrustList.subjectAlgorithm",
        )
        self._subjects = {}
        for subj in (
            CertificateTrustSubject(subject)
            for subject in self.content["trusted_subjects"]
        ):
            self._subjects[subj.identifier.hex().lower()] = subj
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

    .. attribute:: data

       The underlying ASN.1 data object

    .. attribute:: attributes

       A dictionary mapping of attribute types to values.

    The following values are extracted from the attributes:

    .. attribute:: extended_key_usages

       Defines the EKU's the certificate is valid for. It may be empty, which we take
       as 'all is acceptable'.

    .. attribute:: friendly_name

       The friendly name of the certificate.

    .. attribute:: key_identifier

       The sha1 fingerprint of the certificate.

    .. attribute:: subject_name_md5

       The md5 of the subject name.

    .. attribute:: auth_root_sha256

       The sha256 fingerprint of the certificate.

    .. attribute:: disallowed_filetime

       The time since when a certificate has been disabled. Digital signatures with a
       timestamp prior to this date continue to be valid, but use cases after this date
       are prohibited. It may be used in conjunction with
       :attr:`disallowed_extended_key_usages` to define specific EKU's to be disabled.

    .. attribute:: root_program_chain_policies

       A list of EKU's probably used for EV certificates.

    .. attribute:: disallowed_extended_key_usages

       Defines the EKU's the certificate is not valid for. When used in combination with
       :attr:`disallowed_filetime`, the disabled EKU's are only disabled from that date
       onwards, otherwise, it means since the beginning of time.

    .. attribute:: not_before_filetime

       The time since when new certificates from this CA are not trusted. Certificates
       from prior the date will continue to validate. When used in conjunction with
       :attr:`not_before_extended_key_usages`, this only concerns certificates issued
       after this date for the defined EKU's.

    .. attribute:: not_before_extended_key_usages

       Defines the EKU's for which the :attr:`not_before_filetime` is considered. If
       that attribute is not defined, we assume that it means since the beginning of
       time.

    .. warning::

       The interpretation of the various attributes and their implications has been
       reverse-engineered. Though we seem to have a fairly solid understanding, various
       edge-cases may not have been considered.

    """

    extended_key_usages: list[str] | None
    friendly_name: str | None
    key_identifier: bytes
    subject_name_md5: bytes
    auth_root_sha256: bytes
    disallowed_filetime: datetime.datetime | None
    root_program_chain_policies: list[str] | None
    disallowed_extended_key_usages: list[str] | None
    not_before_filetime: datetime.datetime | None
    not_before_extended_key_usages: list[str] | None

    def __init__(self, data: asn1.ctl.TrustedSubject):
        self.data = data
        self._parse()

    def _parse(self) -> None:
        self.identifier = self.data["subject_identifier"].native
        self.attributes = {
            attr["type"].native: attr["values"].native[0]
            for attr in self.data["subject_attributes"]
        }

        self.extended_key_usages = self.attributes.get(
            "microsoft_ctl_enhkey_usage", None
        )
        self.friendly_name = self.attributes.get("microsoft_ctl_friendly_name", None)
        self.key_identifier = self.attributes.get("microsoft_ctl_key_identifier", b"")
        self.subject_name_md5 = self.attributes.get(
            "microsoft_ctl_subject_name_md5_hash", b""
        )
        # TODO: RootProgramCertPolicies not implemented
        self.auth_root_sha256 = self.attributes.get(
            "microsoft_ctl_auth_root_sha256_hash", b""
        )
        self.disallowed_filetime = self.attributes.get(
            "microsoft_ctl_disallowed_filetime", None
        )
        self.root_program_chain_policies = self.attributes.get(
            "microsoft_ctl_root_program_chain_policies", None
        )
        self.disallowed_extended_key_usages = self.attributes.get(
            "microsoft_ctl_disallowed_enhkey_usage", None
        )
        self.not_before_filetime = self.attributes.get(
            "microsoft_ctl_not_before_filetime", None
        )
        self.not_before_extended_key_usages = self.attributes.get(
            "microsoft_ctl_not_before_enhkey_usage", None
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
