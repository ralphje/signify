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

from typing import cast

from pyasn1.type import char, namedtype, tag, univ
from pyasn1_modules import rfc2315, rfc2459


class SpcAttributeTypeAndOptionalValue(univ.Sequence):  # type: ignore[misc]
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", rfc2459.AttributeType()),
        namedtype.OptionalNamedType("value", rfc2459.AttributeValue()),
    )


class SpcIndirectDataContent(univ.Sequence):  # type: ignore[misc]
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("data", SpcAttributeTypeAndOptionalValue()),
        namedtype.NamedType("messageDigest", rfc2315.DigestInfo()),
    )


class SpcUuid(univ.OctetString):  # type: ignore[misc]
    pass


class SpcSerializedObject(univ.Sequence):  # type: ignore[misc]
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("classId", SpcUuid()),
        namedtype.NamedType("serializedData", univ.OctetString()),
    )


class SpcString(univ.Choice):  # type: ignore[misc]
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "unicode",
            char.BMPString().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        ),
        namedtype.NamedType(
            "ascii",
            char.IA5String().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            ),
        ),
    )

    def to_python(self) -> str | None:
        if "unicode" in self:
            return str(self["unicode"])
        elif "ascii" in self:
            return str(self["ascii"])
        return None


class SpcLink(univ.Choice):  # type: ignore[misc]
    """According to Authenticode specification."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "url",
            char.IA5String().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        ),
        namedtype.NamedType(
            "moniker",
            SpcSerializedObject().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            ),
        ),
        namedtype.NamedType(
            "file",
            SpcString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
            ),
        ),
    )

    def to_python(self) -> str | None:
        if "url" in self:
            return str(self["url"])
        elif "moniker" in self:
            return None  # TODO
        elif "file" in self:
            return cast(SpcString, self["file"]).to_python()
        else:
            return None


class SpcSpOpusInfo(univ.Sequence):  # type: ignore[misc]
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "programName",
            SpcString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        ),
        namedtype.OptionalNamedType(
            "moreInfo",
            SpcLink().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            ),
        ),
    )


class SpcStatementType(univ.Sequence):  # type: ignore[misc]
    componentType = univ.ObjectIdentifier()


class SpcRfc3161Timestamp(rfc2315.ContentInfo):  # type: ignore[misc]
    pass


class SpcNestedSignature(rfc2315.ContentInfo):  # type: ignore[misc]
    pass
