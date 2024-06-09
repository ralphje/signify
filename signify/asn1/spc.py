# This is a derivative, modified, work from the verify-sigs project.
# Please refer to the LICENSE file in the distribution for more
# information. Original filename: asn1/spc.py
#
# Parts of this file are licensed as follows:
#
# Copyright 2011 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Authenticode-specific ASN.1 data structures, called
Software Publishing Certificate (SPC).
"""

from __future__ import annotations

from asn1crypto.algos import DigestInfo
from asn1crypto.cms import (
    CMSAttribute,
    CMSAttributeType,
    ContentInfo,
    ContentType,
    EncapsulatedContentInfo,
)
from asn1crypto.core import (
    Any,
    Asn1Value,
    BitString,
    BMPString,
    Boolean,
    Choice,
    IA5String,
    ObjectIdentifier,
    OctetString,
    Sequence,
    SequenceOf,
    SetOf,
)
from asn1crypto.x509 import Extension, ExtensionId

# based on https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx


class SpcUuid(OctetString):  # type: ignore[misc]
    """SpcUuid.

    Based on `Windows Authenticode Portable Executable Signature Format
    <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_::

        SpcUuid ::= OCTETSTRING
    """


class SpcSerializedObject(Sequence):  # type: ignore[misc]
    """SpcSerializedObject.

    Based on `Windows Authenticode Portable Executable Signature Format
    <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_::

        SpcSerializedObject ::= SEQUENCE {
            classId SpcUuid,
            serializedData OCTETSTRING
        }
    """

    _fields = [
        ("class_id", SpcUuid),
        ("serialized_data", OctetString),
    ]


class SpcString(Choice):  # type: ignore[misc]
    """SpcString.

    Based on `Windows Authenticode Portable Executable Signature Format
    <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_::

        SpcString ::= CHOICE {
            unicode [0] IMPLICIT BMPSTRING,
            ascii [1] IMPLICIT IA5STRING
        }
    """

    _alternatives = [
        ("unicode", BMPString, {"implicit": 0}),
        ("ascii", IA5String, {"implicit": 1}),
    ]


class SpcLink(Choice):  # type: ignore[misc]
    """SpcLink.

    Based on `Windows Authenticode Portable Executable Signature Format
    <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_::

        SpcLink ::= CHOICE {
            url [0] IMPLICIT IA5STRING,
            moniker [1] IMPLICIT SpcSerializedObject,
            file [2] EXPLICIT SpcString
        }
    """

    _alternatives = [
        ("url", IA5String, {"implicit": 0}),
        ("moniker", SpcSerializedObject, {"implicit": 1}),
        ("file", SpcString, {"explicit": 2}),
    ]


class SpcImage(Sequence):  # type: ignore[misc]
    """SpcImage.

    Based on the SPC_IMAGE struct in WinTrust.h, e.g. at
    https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/WinTrust/struct.SPC_IMAGE.html
    """

    _fields = [
        ("image_link", SpcLink, {"explicit": 0, "optional": True}),
        ("bitmap", OctetString, {"implicit": 1, "optional": True}),
        ("metafile", OctetString, {"implicit": 2, "optional": True}),
        ("enhanced_metafile", OctetString, {"implicit": 3, "optional": True}),
        ("gif_file", OctetString, {"implicit": 4, "optional": True}),
    ]


class SpcPeImageFlags(BitString):  # type: ignore[misc]
    """SpcPeImageFlags.

    Based on `Windows Authenticode Portable Executable Signature Format
    <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_::

        SpcPeImageFlags ::= BIT STRING {
            includeResources            (0),
            includeDebugInfo            (1),
            includeImportAddressTable   (2)
        }

    """

    _map = {
        0: "include_resources",
        1: "include_debug_info",
        2: "include_import_address_table",
    }


class SpcPeImageData(Sequence):  # type: ignore[misc]
    """SpcPeImageData.

    Based on `Windows Authenticode Portable Executable Signature Format
    <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_::

        SpcPeImageData ::= SEQUENCE {
            flags SpcPeImageFlags DEFAULT { includeResources },
            file SpcLink
        }

    Note that although this is not in the spec, it is actually explicitly tagged.
    And although it is not optional in the spec, it is actually optional as shown in
    the accompanying text. It is possible that the specs for
    ``SpcAttributeTypeAndOptionalValue.value`` and ``SpcPeImageData.file`` were
    accidentally flipped.
    """

    _fields = [
        ("flags", SpcPeImageFlags, {"default": {"include_resources"}}),
        ("file", SpcLink, {"optional": True, "explicit": 0}),
    ]


class SpcAttributeType(ObjectIdentifier):  # type: ignore[misc]
    """Specific attribute type of a SPC attribute."""

    _map: dict[str, str] = {
        "1.3.6.1.4.1.311.2.1.15": "microsoft_spc_pe_image_data",
    }


class SpcAttributeTypeAndOptionalValue(Sequence):  # type: ignore[misc]
    """Attribute type and optional value.

    Based on `Windows Authenticode Portable Executable Signature Format
    <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_::

        SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
            type ObjectID,
            value [0] EXPLICIT ANY OPTIONAL
        }

    Note that although the spec defines this value as explicitly tagged, that's not
    actually the case. It is possible that the specs for
    `SpcAttributeTypeAndOptionalValue.value`` and ``SpcPeImageData.file`` were
    accidentally flipped.
    """

    _fields = [
        ("type", SpcAttributeType),
        ("value", Any, {"optional": True}),
    ]

    _oid_pair = ("type", "value")
    _oid_specs: dict[str, type[Asn1Value]] = {
        "microsoft_spc_pe_image_data": SpcPeImageData,
    }


class SpcIndirectDataContent(Sequence):  # type: ignore[misc]
    """Indirect data content.

    Based on `Windows Authenticode Portable Executable Signature Format
    <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_::

        SpcIndirectDataContent ::= SEQUENCE {
            data SpcAttributeTypeAndOptionalValue,
            messageDigest DigestInfo
        }

    Note: although DigestInfo is explicitly defined in the docs, it is simply a copy of
    the RFC DigestInfo.
    """

    _fields = [
        ("data", SpcAttributeTypeAndOptionalValue),
        ("message_digest", DigestInfo),
    ]


class SpcSpOpusInfo(Sequence):  # type: ignore[misc]
    """SpcSpOpusInfo.

    Based on `Windows Authenticode Portable Executable Signature Format
    <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_::

        SpcSpOpusInfo ::= SEQUENCE {
            programName [0] EXPLICIT SpcString OPTIONAL,
            moreInfo [1] EXPLICIT SpcLink OPTIONAL,
        }

    In WinTrust.h, the value pPublisherInfo is also defined. See
    https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/WinTrust/struct.SPC_SP_OPUS_INFO.html
    """

    _fields = [
        ("program_name", SpcString, {"optional": True, "explicit": 0}),
        ("more_info", SpcLink, {"optional": True, "explicit": 1}),
        ("publisher_info", SpcLink, {"optional": True, "explicit": 2}),
    ]


class SetOfSpcSpOpusInfo(SetOf):  # type: ignore[misc]
    _child_spec = SpcSpOpusInfo


class SpcStatementTypeIdentifier(ObjectIdentifier):  # type: ignore[misc]
    _map: dict[str, str] = {
        "1.3.6.1.4.1.311.2.1.21": "microsoft_spc_individual_sp_key_purpose",
        "1.3.6.1.4.1.311.2.1.22": "microsoft_spc_commercial_sp_key_purpose",
    }


class SpcStatementType(SequenceOf):  # type: ignore[misc]
    """SpcStatementType.

    Based on `MS-OSHARED
    <https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/c541e3e4-3d04-4cbd-82db-1b73163427fd>`_::

        SpcStatementType ::= SEQUENCE of OBJECT IDENTIFIER

    """

    _child_spec = SpcStatementTypeIdentifier


class SetOfSpcStatementType(SetOf):  # type: ignore[misc]
    _child_spec = SpcStatementType


ContentType._map["1.3.6.1.4.1.311.2.1.4"] = "microsoft_spc_indirect_data_content"
EncapsulatedContentInfo._oid_specs["microsoft_spc_indirect_data_content"] = (
    ContentInfo._oid_specs["microsoft_spc_indirect_data_content"]
) = SpcIndirectDataContent

CMSAttributeType._map["1.3.6.1.4.1.311.2.1.11"] = "microsoft_spc_statement_type"
CMSAttributeType._map["1.3.6.1.4.1.311.2.1.12"] = "microsoft_spc_sp_opus_info"
CMSAttribute._oid_specs["microsoft_spc_sp_opus_info"] = SetOfSpcSpOpusInfo
CMSAttribute._oid_specs["microsoft_spc_statement_type"] = SetOfSpcStatementType


# reverse-engineered certificate extensions


class SpcSpAgencyInformation(Sequence):  # type: ignore[misc]
    """Reverse-engineered extension for certificates, indicating certain information
    on certificate policies. Based on
    https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/WinTrust/struct.SPC_SP_AGENCY_INFO.html

    See also
    https://sotharo-meas.medium.com/cve-2019-1388-windows-privilege-escalation-through-uac-22693fa23f5f
    """

    _fields = [
        ("policy_information", SpcLink, {"explicit": 0}),
        ("policy_display_text", SpcString, {"optional": True, "explicit": 1}),
        ("logo_image", SpcImage, {"optional": True, "implicit": 2}),
        ("logo_link", SpcLink, {"optional": True, "explicit": 3}),
    ]


class SpcFinancialCriteria(Sequence):  # type: ignore[misc]
    """Reverse-engineered extension for certificates"""

    _fields = [
        ("financial_info_available", Boolean, {"default": False}),
        ("meets_criteria", Boolean, {"default": False}),
    ]


ExtensionId._map["1.3.6.1.4.1.311.2.1.10"] = "microsoft_spc_sp_agency_info"
Extension._oid_specs["microsoft_spc_sp_agency_info"] = SpcSpAgencyInformation
ExtensionId._map["1.3.6.1.4.1.311.2.1.27"] = "microsoft_spc_financial_criteria"
Extension._oid_specs["microsoft_spc_financial_criteria"] = SpcFinancialCriteria
