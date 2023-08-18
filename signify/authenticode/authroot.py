from __future__ import annotations

import datetime
import hashlib
import pathlib
import struct
from typing import Any, Iterable, Iterator, Type

import mscerts
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.type import univ
from pyasn1.type.base import Asn1Type
from pyasn1_modules import rfc2315
from typing_extensions import Self

from signify import asn1
from signify._typing import HashFunction, OidTuple
from signify.asn1 import guarded_ber_decode
from signify.asn1.helpers import time_to_python
from signify.exceptions import (
    CertificateTrustListParseError,
    CTLCertificateVerificationError,
)
from signify.pkcs7.signeddata import SignedData
from signify.asn1.hashing import _get_digest_algorithm
from signify.x509 import certificates, context

AUTHROOTSTL_PATH = pathlib.Path(mscerts.where(stl=True))


def _lookup_ekus(
    extended_key_usages: Iterable[str] | None = None,
) -> Iterator[OidTuple]:
    """Normally we would be able to use certvalidator for this, but we simply can't
    now we have done this all to ourselves. So we convert the arguments passed to the
    function to a list of all object-ID tuples.
    """

    if not extended_key_usages:
        return

    # create an inverted map for the fancy names that are supported
    from asn1crypto.x509 import KeyPurposeId

    inverted_map = {
        v: tuple(map(int, k.split("."))) for k, v in KeyPurposeId._map.items()
    }

    # now look for all values
    for eku in extended_key_usages:
        if eku in inverted_map:
            yield inverted_map[eku]
        else:
            yield tuple(map(int, eku.split(".")))


class CertificateTrustList(SignedData):
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

    _expected_content_type = asn1.ctl.CertificateTrustList

    subject_usage: Any
    list_identifier: bytes | None
    sequence_number: int
    this_update: datetime.datetime | None
    next_update: datetime.datetime | None
    subject_algorithm: HashFunction

    def _parse(self) -> None:
        super()._parse()

        self.subject_usage = self.content["subjectUsage"][0]
        self.list_identifier = (
            bytes(self.content["listIdentifier"])
            if self.content["listIdentifier"].isValue
            else None
        )
        self.sequence_number = self.content["sequenceNumber"]
        self.this_update = time_to_python(self.content["ctlThisUpdate"])
        self.next_update = time_to_python(self.content["ctlNextUpdate"])
        self.subject_algorithm = _get_digest_algorithm(
            self.content["subjectAlgorithm"],
            location="CertificateTrustList.subjectAlgorithm",
        )
        self._subjects = {}
        for subj in (
            CertificateTrustSubject(subject)
            for subject in self.content["trustedSubjects"]
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
                "The root %s is not in the certificate trust list" % chain[0]
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

        with open(str(path), "rb") as f:
            content, rest = ber_decoder.decode(f.read(), asn1Spec=rfc2315.ContentInfo())
        #
        # from pyasn1 import debug
        # debug.setLogger(debug.Debug('all'))

        if asn1.oids.get(content["contentType"]) is not rfc2315.SignedData:
            raise CertificateTrustListParseError(
                "ContentInfo does not contain SignedData"
            )

        data = guarded_ber_decode(content["content"], asn1_spec=rfc2315.SignedData())

        signed_data = cls(data)
        signed_data._rest_data = rest  # type: ignore[attr-defined]
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

    extended_key_usages: list[OidTuple] | None
    friendly_name: str | None
    key_identifier: bytes
    subject_name_md5: bytes
    auth_root_sha256: bytes
    disallowed_filetime: datetime.datetime | None
    root_program_chain_policies: list[OidTuple] | None
    disallowed_extended_key_usages: list[OidTuple] | None
    not_before_filetime: datetime.datetime | None
    not_before_extended_key_usages: list[OidTuple] | None

    def __init__(self, data: asn1.ctl.TrustedSubject):
        self.data = data
        self._parse()

    def _parse(self) -> None:
        self.identifier = bytes(self.data["subjectIdentifier"])
        self.attributes = self._parse_attributes(self.data["subjectAttributes"])

        self.extended_key_usages = None
        if asn1.ctl.EnhkeyUsage in self.attributes:
            self.extended_key_usages = [
                tuple(x) for x in self.attributes[asn1.ctl.EnhkeyUsage][0]
            ]

        self.friendly_name = None
        if asn1.ctl.FriendlyName in self.attributes:
            self.friendly_name = bytes(
                self.attributes[asn1.ctl.FriendlyName][0]
            ).decode("utf-16")

        self.key_identifier = bytes(
            self.attributes.get(asn1.ctl.KeyIdentifier, [b""])[0]
        )
        self.subject_name_md5 = bytes(
            self.attributes.get(asn1.ctl.SubjectNameMd5Hash, [b""])[0]
        )
        # TODO: RootProgramCertPolicies not implemented
        self.auth_root_sha256 = bytes(
            self.attributes.get(asn1.ctl.AuthRootSha256Hash, [b""])[0]
        )

        self.disallowed_filetime = None
        if asn1.ctl.DisallowedFiletime in self.attributes:
            self.disallowed_filetime = self._filetime_to_datetime(
                self.attributes[asn1.ctl.DisallowedFiletime][0]
            )

        self.root_program_chain_policies = None
        if asn1.ctl.RootProgramChainPolicies in self.attributes:
            self.root_program_chain_policies = [
                tuple(x) for x in self.attributes[asn1.ctl.RootProgramChainPolicies][0]
            ]

        self.disallowed_extended_key_usages = None
        if asn1.ctl.DisallowedEnhkeyUsage in self.attributes:
            self.disallowed_extended_key_usages = [
                tuple(x) for x in self.attributes[asn1.ctl.DisallowedEnhkeyUsage][0]
            ]

        self.not_before_filetime = None
        if asn1.ctl.NotBeforeFiletime in self.attributes:
            self.not_before_filetime = self._filetime_to_datetime(
                self.attributes[asn1.ctl.NotBeforeFiletime][0]
            )

        self.not_before_extended_key_usages = None
        if asn1.ctl.NotBeforeEnhkeyUsage in self.attributes:
            self.not_before_extended_key_usages = [
                tuple(x) for x in self.attributes[asn1.ctl.NotBeforeEnhkeyUsage][0]
            ]

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
        requested_extended_key_usages = set(_lookup_ekus(extended_key_usages))

        # Now check each of the properties
        if self.extended_key_usages and (
            requested_extended_key_usages - set(self.extended_key_usages)
        ):
            raise CTLCertificateVerificationError(
                "The root %s lists its extended key usages, but %s are not present"
                % (
                    self.friendly_name,
                    requested_extended_key_usages - set(self.extended_key_usages),
                )
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
                        "The root %s is disallowed for certificate issued after %s"
                        " (certificate is %s)"
                        % (
                            self.friendly_name,
                            self.not_before_filetime,
                            to_verify_timestamp,
                        )
                    )
                elif any(
                    eku in self.not_before_extended_key_usages
                    for eku in requested_extended_key_usages
                ):
                    raise CTLCertificateVerificationError(
                        "The root %s disallows requested EKU's %s to certificates"
                        " issued after %s (certificate is %s)"
                        % (
                            self.friendly_name,
                            requested_extended_key_usages,
                            self.not_before_filetime,
                            to_verify_timestamp,
                        )
                    )
        elif self.not_before_extended_key_usages is not None and any(
            eku in self.not_before_extended_key_usages
            for eku in requested_extended_key_usages
        ):
            raise CTLCertificateVerificationError(
                "The root %s disallows requested EKU's %s"
                % (self.friendly_name, requested_extended_key_usages)
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
                        "The root %s is disallowed since %s (requested %s)"
                        % (self.friendly_name, self.disallowed_filetime, timestamp)
                    )
                elif any(
                    eku in self.disallowed_extended_key_usages
                    for eku in requested_extended_key_usages
                ):
                    raise CTLCertificateVerificationError(
                        "The root %s is disallowed for EKU's %s since %s (requested %s"
                        " at %s)"
                        % (
                            self.friendly_name,
                            self.disallowed_extended_key_usages,
                            self.disallowed_filetime,
                            requested_extended_key_usages,
                            timestamp,
                        )
                    )
        elif self.disallowed_extended_key_usages is not None and any(
            eku in self.disallowed_extended_key_usages
            for eku in requested_extended_key_usages
        ):
            raise CTLCertificateVerificationError(
                "The root %s disallows requested EKU's %s"
                % (self.friendly_name, requested_extended_key_usages)
            )

        return True

    @classmethod
    def _parse_attributes(
        cls, data: rfc2315.Attributes
    ) -> dict[OidTuple | Type[Asn1Type], list[Any]]:
        """Given a set of Attributes, parses them and returns them as a dict

        :param data: The attributes to process
        """

        result = {}
        for attr in data:
            typ = asn1.oids.get(attr["type"])
            values = []
            for value in attr["values"]:
                if not isinstance(typ, tuple):
                    # This should transparently handle when the data is encapsulated in
                    # an OctetString but we are not expecting an OctetString
                    try:
                        if not isinstance(type, univ.OctetString):
                            _, v = ber_decoder.decode(value, recursiveFlag=0)
                        else:
                            v = value
                        value = guarded_ber_decode(v, asn1_spec=typ())
                    except Exception:
                        value = guarded_ber_decode(value, asn1_spec=typ())
                values.append(value)
            result[typ] = values

        return result

    @classmethod
    def _filetime_to_datetime(
        cls, filetime: univ.OctetString
    ) -> datetime.datetime | None:
        if not filetime:
            return None

        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        value = struct.unpack("<Q", bytes(filetime))[0]
        return epoch + datetime.timedelta(microseconds=value / 10)
