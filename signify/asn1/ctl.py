from __future__ import annotations

import datetime
import struct
from typing import Any, cast

from asn1crypto.algos import DigestAlgorithm, DigestAlgorithmId
from asn1crypto.cms import (
    ContentInfo,
    ContentType,
    EncapsulatedContentInfo,
    SetOfAny,
    SetOfOctetString,
)
from asn1crypto.core import (
    AbstractString,
    Asn1Value,
    BMPString,
    Choice,
    Integer,
    ObjectIdentifier,
    OctetString,
    ParsableOctetString,
    Sequence,
    SequenceOf,
    SetOf,
)
from asn1crypto.util import utc_with_dst
from asn1crypto.x509 import (
    CertificatePolicies,
    Extensions,
    ExtKeyUsageSyntax,
    PolicyQualifierId,
    Time,
)

from signify.asn1.spc import SetOfSpcIndirectDataContent, SpcLink

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


class SubjectUsageObjectIdentifier(ObjectIdentifier):  # type: ignore[misc]
    _map = {
        "1.3.6.1.4.1.311.10.3.9": "microsoft_root_list_signer",
        "1.3.6.1.4.1.311.12.1.1": "microsoft_catalog_list",
        "1.3.6.1.4.1.311.20.1": "microsoft_auto_enroll_ctl_usage",
    }


class SubjectUsage(SequenceOf):  # type: ignore[misc]
    """Subject usage of the CTL structure.

    Based on `MS-CAESO
    <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf>`_::

        SubjectUsage ::= EnhancedKeyUsage
    """

    _child_spec = SubjectUsageObjectIdentifier


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
        "1.3.6.1.4.1.311.2.1.4": "microsoft_spc_indirect_data_content",
        "1.3.6.1.4.1.311.12.2.1": "microsoft_cat_namevalue",
        "1.3.6.1.4.1.311.12.2.2": "microsoft_cat_memberinfo",
        "1.3.6.1.4.1.311.12.2.3": "microsoft_cat_memberinfo2",
    }


class CTLString(AbstractString, OctetString):  # type: ignore[misc]
    _encoding = "utf-16-le"

    def __unicode__(self) -> str:
        return cast(str, super().__unicode__().rstrip("\0"))


class SetOfCTLString(SetOf):  # type: ignore[misc]
    _child_spec = CTLString


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


class SetOfFileTime(SetOf):  # type: ignore[misc]
    _child_spec = FileTime


class NameValue(Sequence):  # type: ignore[misc]
    """Based on the CAT_NAMEVALUE struct in WinTrust.h, e.g. at
    https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/WinTrust/struct.CAT_NAMEVALUE.html::

        NameValue ::= SEQUENCE {
            refname     BMPSTRING,
            typeaction  INTEGER,
            value       OCTETSTRING
        }
    """

    _fields = [
        ("refname", BMPString),
        ("typeaction", Integer),
        ("value", CTLString),
    ]


class NameValues(SetOf):  # type: ignore[misc]
    _child_spec = NameValue


class MemberInfo(Sequence):  # type: ignore[misc]
    """Based on the CAT_MEMBERINFO struct in WinTrust.h, e.g. at
    https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/WinTrust/struct.CAT_MEMBERINFO.html::

        MemberInfo ::= SEQUENCE {
            subguid     BMPSTRING,
            certversion INTEGER
        }
    """

    _fields = [
        ("subguid", BMPString),
        ("certversion", Integer),
    ]


class SetOfMemberInfo(SetOf):  # type: ignore[misc]
    _child_spec = MemberInfo


class MemberInfo2(Choice):  # type: ignore[misc]
    """Based on the CAT_MEMBERINFO2 struct in WinTrust.h, e.g. at
    https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/WinTrust/struct.CAT_MEMBERINFO2.html

    However, this does not fully align with the ASN.1 structure observed, and since
    none of the examples seem to fill it in, we can simply skip for now.
    """

    _alternatives = [
        ("subject_guid", OctetString, {"implicit": 0}),
        ("cert_version", OctetString, {"implicit": 1}),
        ("unknown2", OctetString, {"implicit": 2}),
    ]


class SetOfMemberInfo2(SetOf):  # type: ignore[misc]
    _child_spec = MemberInfo2


class SetOfParsableOctetString(SetOf):  # type: ignore[misc]
    """A set of ParsableOctetStrings where the values are interpreted as a DER encoded
    value.
    """

    _child_spec = ParsableOctetString

    def parse(
        self, spec: type[Asn1Value] | None = None, spec_params: Any = None
    ) -> Any:
        if not spec:
            return self.children  # type: ignore[has-type]
        self.children = [child.parse(spec=spec) for child in self]
        return self.children


class SubjectAttribute(Sequence):  # type: ignore[misc]
    """Subject attributes of the trusted subject in the CTL structure.

    Based on `MS-CAESO
    <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf>`_.
    """

    _fields = [
        ("type", SubjectAttributeType),
        ("values", None),
    ]
    _oid_specs: dict[str, type[Asn1Value] | tuple[type[Asn1Value], type[Asn1Value]]] = {
        "microsoft_ctl_enhkey_usage": (SetOfParsableOctetString, ExtKeyUsageSyntax),
        "microsoft_ctl_friendly_name": SetOfCTLString,
        "microsoft_ctl_key_identifier": SetOfOctetString,
        "microsoft_ctl_subject_name_md5_hash": SetOfOctetString,
        "microsoft_ctl_root_program_cert_policies": (
            SetOfParsableOctetString,
            CertificatePolicies,
        ),
        "microsoft_ctl_auth_root_sha256_hash": SetOfOctetString,
        "microsoft_ctl_disallowed_filetime": SetOfFileTime,
        "microsoft_ctl_root_program_chain_policies": (
            SetOfParsableOctetString,
            ExtKeyUsageSyntax,
        ),
        "microsoft_ctl_disallowed_enhkey_usage": (
            SetOfParsableOctetString,
            ExtKeyUsageSyntax,
        ),
        "microsoft_ctl_not_before_filetime": SetOfFileTime,
        "microsoft_ctl_not_before_enhkey_usage": (
            SetOfParsableOctetString,
            ExtKeyUsageSyntax,
        ),
        "microsoft_spc_indirect_data_content": SetOfSpcIndirectDataContent,
        "microsoft_cat_namevalue": NameValues,
        "microsoft_cat_memberinfo": SetOfMemberInfo,
        "microsoft_cat_memberinfo2": SetOfMemberInfo2,
    }

    def _values_spec(
        self,
    ) -> type[Asn1Value] | tuple[type[Asn1Value], type[Asn1Value]]:
        return self._oid_specs.get(self["type"].native, SetOfAny)

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

# Add the catalog list member as digest algorithm
DigestAlgorithmId._map["1.3.6.1.4.1.311.12.1.2"] = "microsoft_catalog_list_member"
DigestAlgorithmId._map["1.3.6.1.4.1.311.12.1.3"] = "microsoft_catalog_list_member_v2"

# Add PolicyQualifierId (used in microsoft_ctl_root_program_cert_policies)
PolicyQualifierId._map["1.3.6.1.4.1.311.60.1.1"] = "microsoft_root_program_flags"
