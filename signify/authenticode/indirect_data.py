from __future__ import annotations

import hashlib
import struct
import warnings
from collections.abc import Iterable
from typing import ClassVar, cast

from asn1crypto.core import Asn1Value
from typing_extensions import Literal

from signify._typing import HashFunction
from signify.asn1 import spc
from signify.asn1.hashing import _get_digest_algorithm
from signify.asn1.spc import SpcPeImageData, SpcSigInfo
from signify.exceptions import (
    AuthenticodeParseError,
)


class PeImageData:
    """Information about the PE file, as provided in the :class:`IndirectData`. It
    is based on the following structure::

        SpcPeImageData ::= SEQUENCE {
            flags SpcPeImageFlags DEFAULT { includeResources },
            file SpcLink
        }
        SpcPeImageFlags ::= BIT STRING {
            includeResources            (0),
            includeDebugInfo            (1),
            includeImportAddressTable   (2)
        }
        SpcLink ::= CHOICE {
            url      [0] IMPLICIT IA5STRING,
            moniker  [1] IMPLICIT SpcSerializedObject,
            file     [2] EXPLICIT SpcString
        }
        SpcSerializedObject ::= SEQUENCE {
            classId SpcUuid,
            serializedData OCTETSTRING
        }

    This structure contains flags, which define which parts of the PE file are hashed.
    It is always ignored.

    The file attribute originally contained information that describes the software
    publisher, but can now be a URL (which is ignored), a file, which is set to a
    SpcString set to ``<<<Obsolete>>>``, or the moniker setting a SpcSerializedObject.

    If used, the moniker always has UUID a6b586d5-b4a1-2466-ae05-a217da8e60d6
    (bytes ``a6 b5 86 d5 b4 a1 24 66  ae 05 a2 17 da 8e 60 d6``), and a binary
    structure. Ominously, this is left outside of scope of the Authenticode
    documentation, noting that it contains a binary structure that contains page hashes.

    """

    def __init__(self, asn1: spc.SpcPeImageData):
        self.asn1 = asn1

    @property
    def flags(self) -> set[str]:
        """Defines which parts of the PE file are hashed. It is always ignored."""
        return cast("set[str]", self.asn1["flags"].native)

    @property
    def file_link_type(self) -> Literal["url", "moniker", "file"]:
        """Describes which of the options is used in this content."""
        return cast(Literal["url", "moniker", "file"], self.asn1["file"].name)

    @property
    def publisher(self) -> str:
        """Available if :attr:`file_link_type` is ``url`` or ``file``.
        Contains the information in the attribute in string form.
        """
        if self.file_link_type not in {"url", "file"}:
            raise AttributeError(
                "Property only available when file_link_type is url or file."
            )
        return cast(str, self.asn1["file"].native)

    @property
    def class_id(self) -> str:
        """Available if :attr:`file_link_type` is ``moniker``.
        Contains the class ID. Should be a6b586d5-b4a1-2466-ae05-a217da8e60d6.
        """
        if self.file_link_type != "moniker":
            raise AttributeError(
                "Property only available when file_link_type is moniker."
            )
        return cast(str, self.asn1["file"].chosen["class_id"].native)

    @property
    def serialized_data(self) -> bytes:
        """Available if :attr:`file_link_type` is ``moniker``.
        Raw serialized data as bytes.
        """
        if self.file_link_type != "moniker":
            raise AttributeError(
                "Property only available when file_link_type is moniker."
            )
        return bytes(self.asn1["file"].chosen["serialized_data"])

    @property
    def serialized_data_asn1_available(self) -> bool:
        """Defines whether the property :attr:`serialized_data_asn1` is available."""
        return (
            self.file_link_type == "moniker"
            and self.class_id == "a6b586d5-b4a1-2466-ae05-a217da8e60d6"
        )

    @property
    def serialized_data_asn1(self) -> list[spc.SpcAttributeTypeAndOptionalValue]:
        """Available if :attr:`serialized_data_asn1_available` is :const:`True`.
        Return the data in ASN.1 form.
        """
        if not self.serialized_data_asn1_available:
            raise AttributeError("Serialized data unavailable.")
        return cast(
            "list[spc.SpcAttributeTypeAndOptionalValue]",
            self.asn1["file"].chosen["serialized_data"].parsed,
        )

    @property
    def content_pairs(self) -> Iterable[tuple[str, list[bytes]]]:
        """Available if :attr:`serialized_data_asn1_available` is :const:`True`."""
        for attr in self.serialized_data_asn1:
            yield attr["type"].native, attr["value"].native

    @property
    def content_types(self) -> list[str]:
        """Available if :attr:`serialized_data_asn1_available` is :const:`True`."""
        return [c["type"].native for c in self.serialized_data_asn1]

    @property
    def content_type(self) -> str:
        """Available if :attr:`serialized_data_asn1_available` is :const:`True`."""
        if len(self.content_types) == 1:
            return self.content_type[0]
        raise AttributeError(
            "SpcPeImageData.content_types contained multiple content types"
        )

    @property
    def contents(self) -> list[list[bytes]]:
        """Available if :attr:`serialized_data_asn1_available` is :const:`True`."""
        return [c["value"].native for c in self.serialized_data_asn1]

    @property
    def content(self) -> list[bytes]:
        """Available if :attr:`serialized_data_asn1_available` is :const:`True`."""
        if len(self.contents) == 1:
            return self.contents[0]
        raise AttributeError("SpcPeImageData.contents contained multiple entries")

    @property
    def page_hashes(self) -> Iterable[tuple[int, int, bytes, HashFunction]]:
        """Iterates over all page hash ranges, and their hash digests, as defined
        in the SpcSerializedObject. If not available, will simply return an empty list.
        """
        if not self.serialized_data_asn1_available:
            return
        for content_type, contents in self.content_pairs:
            hash_algorithm = self.page_hash_algorithm(content_type)
            for content in contents:
                for start, end, digest in self.parse_page_hash_content(
                    hash_algorithm, content
                ):
                    yield start, end, digest, hash_algorithm

    PAGE_HASH_ALGORITHMS: ClassVar[dict[str, HashFunction]] = {
        "microsoft_spc_pe_image_page_hashes_v1": hashlib.sha1,
        "microsoft_spc_pe_image_page_hashes_v2": hashlib.sha256,
    }

    @classmethod
    def page_hash_algorithm(cls, content_type: str) -> HashFunction:
        """Returns the used page hash algorithm for the provided content type."""
        if content_type not in cls.PAGE_HASH_ALGORITHMS:
            raise AuthenticodeParseError(
                f"Unknown content type for page hashes: {content_type!r}"
            )
        return cls.PAGE_HASH_ALGORITHMS[content_type]

    @property
    def page_hash_algorithms(self) -> list[HashFunction]:
        """Returns all used page hash algorithms in this structure."""
        return [
            self.page_hash_algorithm(content_type)
            for content_type in self.content_types
        ]

    @classmethod
    def parse_page_hash_content(
        cls, hash_algorithm: HashFunction, content: bytes
    ) -> Iterable[tuple[int, int, bytes]]:
        """Parses the content in the page hash content blob. It is constructed
        as 4 bytes offset, and the hash digest. The final entry will be the final offset
        and a zero hash (``0000...``).

        This method yields tuples of start offset, end offset, and the hash digest.
        """

        d = hash_algorithm()
        d.update(b"")
        hash_length = len(d.digest())

        position, previous_offset, digest = 0, None, None
        while position < len(content):
            offset = struct.unpack("<I", content[position : position + 4])[0]
            if previous_offset is not None and digest is not None:
                yield previous_offset, offset, digest

            digest = content[position + 4 : position + 4 + hash_length]
            previous_offset = offset
            position += 4 + hash_length


class SigInfo:
    """SigInfo, mostly used in MSI files. It defines information about the SIP, which
    is the Subject Interface Package: A Microsoft proprietary specification for a
    software layer that enables applications to create, store, retrieve, and verify a
    subject signature.
    """

    def __init__(self, asn1: spc.SpcSigInfo):
        self.asn1 = asn1

    @property
    def sip_version(self) -> int:
        """The SIP version."""
        return cast(int, self.asn1["sip_version"].native)

    @property
    def sip_guid(self) -> str:
        """The SIP GUID."""
        return cast(str, self.asn1["sip_guid"].native)


class IndirectData:
    """The Authenticode's SpcIndirectDataContent information, and their children. This
    is expected to be part of the content of the SignedData structure in Authenticode.

    Note that this structure is completely flattened out from this ASN.1 spec::

        SpcIndirectDataContent ::= SEQUENCE {
            data SpcAttributeTypeAndOptionalValue,
            messageDigest  DigestInfo
        }
        SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
            type ObjectID,
            value [0] EXPLICIT ANY OPTIONAL
        }

    .. attribute:: asn1

       The underlying ASN.1 data object

    """

    def __init__(self, asn1: spc.SpcIndirectDataContent):
        self.asn1 = asn1

    @property
    def content_type(self) -> str:
        """The contenttype string"""
        return cast(str, self.asn1["data"]["type"].native)

    @property
    def content_asn1(self) -> Asn1Value:
        """ASN.1 structure of the content."""
        if self.content_type not in {
            "microsoft_spc_pe_image_data",
            "microsoft_spc_siginfo",
        }:
            warnings.warn(
                f"SpcInfo contains unknown content type {self.content_type!r}",
                stacklevel=2,
            )
        return cast(Asn1Value, self.asn1["data"]["value"])

    @property
    def content(self) -> PeImageData | SigInfo | None:
        """Nested content of this :class:`IndirectData`."""
        if self.content_type == "microsoft_spc_pe_image_data":
            return PeImageData(cast(SpcPeImageData, self.content_asn1))
        elif self.content_type == "microsoft_spc_siginfo":
            return SigInfo(cast(SpcSigInfo, self.content_asn1))
        warnings.warn(
            f"SpcInfo contains unknown content type {self.content_type!r}",
            stacklevel=2,
        )
        return None

    @property
    def digest_algorithm(self) -> HashFunction:
        """Digest algorithm of the :attr:`digest`."""
        return _get_digest_algorithm(
            self.asn1["message_digest"]["digest_algorithm"],
            location="SpcIndirectDataContent.digestAlgorithm",
        )

    @property
    def digest(self) -> bytes:
        """The (signed) digest as present in this structure. This should match the
        digest calculated over the data itself.
        """
        return cast(bytes, self.asn1["message_digest"]["digest"].native)
