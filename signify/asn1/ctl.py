from __future__ import annotations

import datetime
import struct
from typing import Any, cast

from asn1crypto.algos import DigestAlgorithm
from asn1crypto.cms import ContentInfo, ContentType, EncapsulatedContentInfo
from asn1crypto.core import (
    Asn1Value,
    BMPString,
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    SequenceOf,
    SetOf,
)
from asn1crypto.util import utc_with_dst
from asn1crypto.x509 import Extensions, ExtKeyUsageSyntax, Time

# Based on https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf


class CTLVersion(Integer):  # type: ignore[misc]
    """Version of the CTL structure.

    Based on `MS-CAESO
    <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf>`_::

        CTLVersion ::= INTEGER {v1(0)}
    """

    _map = {
        0: "v1",
    }


class SubjectUsage(ExtKeyUsageSyntax):  # type: ignore[misc]
    """Subject usage of the CTL structure.

    Based on `MS-CAESO
    <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf>`_::

        SubjectUsage ::= EnhancedKeyUsage
    """


class ListIdentifier(OctetString):  # type: ignore[misc]
    """List identifier of the CTL structure.

    Based on `MS-CAESO
    <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf>`_::

         ListIdentifier ::= OCTETSTRING
    """


class SubjectIdentifier(OctetString):  # type: ignore[misc]
    """Subject identifier of the CTL structure.

    Based on `MS-CAESO
    <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf>`_::

         SubjectIdentifier ::= OCTETSTRING
    """


class SubjectAttributeType(ObjectIdentifier):  # type: ignore[misc]
    _map = {
        "1.3.6.1.4.1.311.10.11.9": "microsoft_ctl_enhkey_usage",
        "1.3.6.1.4.1.311.10.11.11": "microsoft_ctl_friendly_name",
        "1.3.6.1.4.1.311.10.11.20": "microsoft_ctl_key_identifier",
        "1.3.6.1.4.1.311.10.11.29": "microsoft_ctl_subject_name_md5_hash",
        "1.3.6.1.4.1.311.10.11.83": "microsoft_ctl_root_program_cert_policies",
        "1.3.6.1.4.1.311.10.11.98": "microsoft_ctl_auth_root_sha256_hash",
        "1.3.6.1.4.1.311.10.11.104": "microsoft_ctl_disallowed_filetime",
        "1.3.6.1.4.1.311.10.11.105": "microsoft_ctl_root_program_chain_policies",
        "1.3.6.1.4.1.311.10.11.122": "microsoft_ctl_disallowed_enhkey_usage",
        "1.3.6.1.4.1.311.10.11.126": "microsoft_ctl_not_before_filetime",
        "1.3.6.1.4.1.311.10.11.127": "microsoft_ctl_not_before_enhkey_usage",
    }


class SetOfSpecificOctetString(SetOf):  # type: ignore[misc]
    """Specific implementation of a SetOf OctetString that allows parsing directly as
    a value, or as a sequence, depending on the child type.
    """

    _child_spec = OctetString
    children: Any

    def parse(
        self, spec: type[Asn1Value] | None = None, spec_params: Any = None
    ) -> Any:
        if not spec:
            return self.children
        if issubclass(spec, SequenceOf):
            self.children = [spec.load(child.contents) for child in self]
        else:
            self.children = [spec(contents=child.contents) for child in self]
        return self.children


class CTLString(BMPString):  # type: ignore[misc]
    _encoding = "utf-16-le"

    def __unicode__(self) -> str:
        return cast(str, super().__unicode__().rstrip("\0"))


class FileTime(OctetString):  # type: ignore[misc]
    _epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    _native: datetime.datetime | None

    @property
    def native(self) -> datetime.datetime | None:
        if self.contents is None or not self.contents:
            return None

        if self._native is None:
            value = struct.unpack("<Q", self.contents)[0]
            self._native = self._epoch + datetime.timedelta(microseconds=value / 10)

        return self._native

    def set(self, value: Any) -> None:
        if isinstance(value, datetime.datetime):
            if not value.tzinfo:
                raise ValueError("Must be timezone aware")
            value = value.astimezone(utc_with_dst)
            value = struct.pack("<Q", int((value - self._epoch).total_seconds() * 100))
        OctetString.set(self, value)
        self._native = None


class SubjectAttribute(Sequence):  # type: ignore[misc]
    """Subject attributes of the trusted subject in the CTL structure.

    Based on `MS-CAESO
    <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf>`_.
    """

    _fields = [
        ("type", SubjectAttributeType),
        ("values", SetOfSpecificOctetString),
    ]
    _oid_specs: dict[str, type[Asn1Value]] = {
        "microsoft_ctl_enhkey_usage": ExtKeyUsageSyntax,
        "microsoft_ctl_friendly_name": CTLString,
        # "microsoft_ctl_key_identifier": OctetString,
        # "microsoft_ctl_subject_name_md5_hash": OctetString,
        # "microsoft_ctl_root_program_cert_policies": ExtKeyUsageSyntax,
        # "microsoft_ctl_auth_root_sha256_hash": OctetString,
        "microsoft_ctl_disallowed_filetime": FileTime,
        "microsoft_ctl_root_program_chain_policies": ExtKeyUsageSyntax,
        "microsoft_ctl_disallowed_enhkey_usage": ExtKeyUsageSyntax,
        "microsoft_ctl_not_before_filetime": FileTime,
        "microsoft_ctl_not_before_enhkey_usage": ExtKeyUsageSyntax,
    }

    def _values_spec(self) -> type[Asn1Value] | None:
        return self._oid_specs.get(self["type"].native, None)

    _spec_callbacks = {"values": _values_spec}


class SubjectAttributes(SetOf):  # type: ignore[misc]
    """Subject attributes of the trusted subject in the CTL structure.

    Based on `MS-CAESO
    <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf>`_.
    """

    _child_spec = SubjectAttribute


class TrustedSubject(Sequence):  # type: ignore[misc]
    """Trusted subject in the CTL structure.

    Based on `MS-CAESO
    <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf>`_::

         TrustedSubject ::= SEQUENCE{
            subjectIdentifier SubjectIdentifier,
            subjectAttributes Attributes OPTIONAL
         }
    """

    _fields = [
        ("subject_identifier", SubjectIdentifier),
        ("subject_attributes", SubjectAttributes, {"optional": True}),
    ]


class TrustedSubjects(SequenceOf):  # type: ignore[misc]
    """Trusted subjects in the CTL structure.

    Based on `MS-CAESO
    <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf>`_::

        TrustedSubjects ::= SEQUENCE OF TrustedSubject
    """

    _child_spec = TrustedSubject


class CertificateTrustList(Sequence):  # type: ignore[misc]
    """CTL structure.

    Based on `MS-CAESO
    <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf>`_::

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
    """

    _fields = [
        ("version", CTLVersion, {"default": "v1"}),
        ("subject_usage", SubjectUsage),
        ("list_identifier", ListIdentifier, {"optional": True}),
        ("sequence_number", Integer, {"optional": True}),
        ("ctl_this_update", Time),
        ("ctl_next_update", Time, {"optional": True}),
        ("subject_algorithm", DigestAlgorithm),
        ("trusted_subjects", TrustedSubjects, {"optional": True}),
        ("ctl_extensions", Extensions, {"optional": True, "explicit": 0}),
    ]


# Add CTL to acceptable options
ContentType._map["1.3.6.1.4.1.311.10.1"] = "microsoft_ctl"
ContentInfo._oid_specs["microsoft_ctl"] = EncapsulatedContentInfo._oid_specs[
    "microsoft_ctl"
] = CertificateTrustList
