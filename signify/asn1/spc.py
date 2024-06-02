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

"""Authenticode-specific ASN.1 data structures."""

from __future__ import annotations

from asn1crypto.algos import DigestInfo
from asn1crypto.cms import (
    CMSAttribute,
    CMSAttributeType,
    ContentInfo,
    ContentType,
    EncapsulatedContentInfo,
    SetOfContentInfo,
)
from asn1crypto.core import (
    Any,
    Asn1Value,
    BMPString,
    Choice,
    IA5String,
    ObjectIdentifier,
    OctetString,
    Sequence,
    SetOf,
)


class SpcAttributeType(ObjectIdentifier):  # type: ignore[misc]
    _map: dict[str, str] = {}


class SpcAttributeTypeAndOptionalValue(Sequence):  # type: ignore[misc]
    _fields = [
        ("type", SpcAttributeType),
        ("value", Any, {"optional": True}),
    ]

    _oid_pair = ("type", "value")
    _oid_specs: dict[str, type[Asn1Value]] = {}


class SpcIndirectDataContent(Sequence):  # type: ignore[misc]
    _fields = [
        ("data", SpcAttributeTypeAndOptionalValue),
        ("message_digest", DigestInfo),
    ]


class SpcUuid(OctetString):  # type: ignore[misc]
    pass


class SpcSerializedObject(Sequence):  # type: ignore[misc]
    _fields = [
        ("class_id", SpcUuid),
        ("serialized_data", OctetString),
    ]


class SpcString(Choice):  # type: ignore[misc]
    _alternatives = [
        ("unicode", BMPString, {"implicit": 0}),
        ("ascii", IA5String, {"implicit": 1}),
    ]


class SpcLink(Choice):  # type: ignore[misc]
    _alternatives = [
        ("url", IA5String, {"implicit": 0}),
        ("moniker", SpcSerializedObject, {"implicit": 1}),
        ("file", SpcString, {"implicit": 2}),
    ]


class SpcSpOpusInfo(Sequence):  # type: ignore[misc]
    _fields = [
        ("program_name", SpcString, {"optional": True, "explicit": 0}),
        ("more_info", SpcLink, {"optional": True, "explicit": 1}),
    ]


class SetOfSpcSpOpusInfo(SetOf):  # type: ignore[misc]
    _child_spec = SpcSpOpusInfo


class SpcStatementType(ObjectIdentifier):  # type: ignore[misc]
    _map: dict[str, str] = {}


ContentType._map["1.3.6.1.4.1.311.2.1.4"] = "microsoft_spc_indirect_data_content"
EncapsulatedContentInfo._oid_specs["microsoft_spc_indirect_data_content"] = (
    ContentInfo._oid_specs["microsoft_spc_indirect_data_content"]
) = SpcIndirectDataContent

CMSAttributeType._map["1.3.6.1.4.1.311.2.1.12"] = "microsoft_spc_sp_opus_info"
CMSAttribute._oid_specs["microsoft_spc_sp_opus_info"] = SetOfSpcSpOpusInfo
