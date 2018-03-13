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

from .pkcs7 import DigestInfo
from pyasn1.type import char
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ
from . import x509


class SpcAttributeTypeAndOptionalValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', x509.AttributeType()),
        namedtype.OptionalNamedType('value', x509.AttributeValue())
    )


class SpcIndirectDataContent(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('data', SpcAttributeTypeAndOptionalValue()),
        namedtype.NamedType('messageDigest', DigestInfo()))


class SpcUuid(univ.OctetString):
    pass


class SpcSerializedObject(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('classId', SpcUuid()),
        namedtype.NamedType('serializedData', univ.OctetString()))


class SpcString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('unicode', char.BMPString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )),
        namedtype.NamedType('ascii', char.IA5String().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        ))
    )

    def to_python(self):
        if 'unicode' in self:
            return str(self['unicode'])
        else:
            return str(self['ascii'])


class SpcLink(univ.Choice):
    """According to Authenticode specification."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('url', char.IA5String().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )),
        namedtype.NamedType('moniker', SpcSerializedObject().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        )),
        namedtype.NamedType('file', SpcString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
        ))
    )


class SpcSpOpusInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('programName', SpcString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )),
        namedtype.OptionalNamedType('moreInfo', SpcLink().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        ))
    )
