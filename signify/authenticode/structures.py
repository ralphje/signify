#!/usr/bin/env python

# This is a derivative, modified, work from the verify-sigs project.
# Please refer to the LICENSE file in the distribution for more
# information. Original filename: auth_data.py
#
# Parts of this file are licensed as follows:
#
# Copyright 2010 Google Inc. All Rights Reserved.
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

"""This module effectively implements Microsoft's documentation on
`<http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx>`_.
"""

from __future__ import annotations

import datetime
import enum
import hashlib
import logging
import pathlib
import struct
import warnings
from collections.abc import Iterable, Iterator, Sequence
from typing import TYPE_CHECKING, Any, Callable, ClassVar, cast

import mscerts
from asn1crypto import cms, tsp
from asn1crypto.core import Asn1Value
from typing_extensions import Literal, ParamSpec

from signify import asn1
from signify._typing import HashFunction
from signify.asn1 import spc
from signify.asn1.hashing import _get_digest_algorithm
from signify.asn1.helpers import accuracy_to_python
from signify.asn1.spc import SpcPeImageData, SpcSigInfo
from signify.authenticode.authroot import CertificateTrustList
from signify.exceptions import (
    AuthenticodeCounterSignerError,
    AuthenticodeInconsistentDigestAlgorithmError,
    AuthenticodeInvalidAdditionalHashError,
    AuthenticodeInvalidDigestError,
    AuthenticodeNotSignedError,
    AuthenticodeParseError,
    CertificateVerificationError,
    CounterSignerError,
    InvalidDigestError,
    ParseError,
    VerificationError,
)
from signify.pkcs7 import CounterSignerInfo, SignedData, SignerInfo
from signify.x509 import (
    Certificate,
    CertificateName,
    CertificateStore,
    FileSystemCertificateStore,
    VerificationContext,
)

if TYPE_CHECKING:
    from signify.authenticode import signed_file

logger = logging.getLogger(__name__)

CERTIFICATE_LOCATION = pathlib.Path(mscerts.where(stl=False))
TRUSTED_CERTIFICATE_STORE_NO_CTL = FileSystemCertificateStore(
    location=CERTIFICATE_LOCATION, trusted=True
)
TRUSTED_CERTIFICATE_STORE = FileSystemCertificateStore(
    location=CERTIFICATE_LOCATION,
    trusted=True,
    ctl=CertificateTrustList.from_stl_file(),
)

_P = ParamSpec("_P")


class AuthenticodeVerificationResult(enum.Enum):
    """This represents the result of an Authenticode verification. If everything is OK,
    it will equal to ``AuthenticodeVerificationResult.OK``, otherwise one of the
    other enum items will be returned. Remember that onl the first exception is
    processed - there may be more wrong.
    """

    OK = enum.auto()
    """The signature is valid."""
    NOT_SIGNED = enum.auto()
    """The provided PE file is not signed."""
    PARSE_ERROR = enum.auto()
    """The Authenticode signature could not be parsed."""
    VERIFY_ERROR = enum.auto()
    """The Authenticode signature could not be verified. This is a more generic error
    than other possible statuses and is used as a catch-all.
    """
    UNKNOWN_ERROR = enum.auto()
    """An unknown error occurred during parsing or verifying."""
    CERTIFICATE_ERROR = enum.auto()
    """An error occurred during the processing of a certificate (e.g. during chain
    building), or when verifying the certificate's signature.
    """
    INCONSISTENT_DIGEST_ALGORITHM = enum.auto()
    """A highly specific error raised when different digest algorithms are used in
    SignedData, SpcInfo or SignerInfo.
    """
    INVALID_DIGEST = enum.auto()
    """The verified digest does not match the calculated digest of the file. This is a
    tell-tale sign that the file may have been tampered with.
    """
    COUNTERSIGNER_ERROR = enum.auto()
    """Something went wrong when verifying the countersignature."""
    INVALID_ADDITIONAL_HASH = enum.auto()
    """The additional file hash, such as the page hash for PE files, or the
    extended digest for MSI files, does not match the calculated hash.
    """

    @classmethod
    def call(
        cls, function: Callable[_P, Any], *args: _P.args, **kwargs: _P.kwargs
    ) -> tuple[AuthenticodeVerificationResult, Exception | None]:
        try:
            function(*args, **kwargs)
        except AuthenticodeNotSignedError as exc:
            return cls.NOT_SIGNED, exc
        except AuthenticodeInconsistentDigestAlgorithmError as exc:
            return cls.INCONSISTENT_DIGEST_ALGORITHM, exc
        except AuthenticodeInvalidDigestError as exc:
            return cls.INVALID_DIGEST, exc
        except AuthenticodeInvalidAdditionalHashError as exc:
            return cls.INVALID_ADDITIONAL_HASH, exc
        except AuthenticodeCounterSignerError as exc:
            return cls.COUNTERSIGNER_ERROR, exc
        except CertificateVerificationError as exc:
            return cls.CERTIFICATE_ERROR, exc
        except ParseError as exc:
            return cls.PARSE_ERROR, exc
        except VerificationError as exc:
            return cls.VERIFY_ERROR, exc
        except Exception as exc:
            return cls.UNKNOWN_ERROR, exc
        else:
            return cls.OK, None


class AuthenticodeCounterSignerInfo(CounterSignerInfo):
    """Subclass of :class:`CounterSignerInfo` that is used to contain the
    countersignerinfo for Authenticode.
    """


class AuthenticodeSignerInfo(SignerInfo):
    """Subclass of :class:`SignerInfo` that is used by the verification of Authenticode.
    Note that this will contain the same attributes as :class:`SignerInfo`, with
    some additions.

    The :attr:`countersigner` attribute can hold the same as in the normal
    :class:`SignerInfo`, but may also contain a :class:`RFC3161SignedData` class.
    """

    parent: AuthenticodeSignedData

    _singular_authenticated_attributes = (
        *SignerInfo._singular_authenticated_attributes,
        "microsoft_spc_statement_type",
        "microsoft_spc_sp_opus_info",
    )
    _singular_unauthenticated_attributes = (
        *SignerInfo._singular_unauthenticated_attributes,
        "microsoft_time_stamp_token",
    )
    _countersigner_class = AuthenticodeCounterSignerInfo
    _expected_content_type = "microsoft_spc_indirect_data_content"

    def _validate_asn1(self) -> None:
        super()._validate_asn1()

        # - Authenticode can be signed using a RFC-3161 timestamp, so we discover this
        # possibility here
        if (
            "counter_signature" in self.unauthenticated_attributes
            and "microsoft_time_stamp_token" in self.unauthenticated_attributes
        ):
            raise AuthenticodeParseError(
                "Countersignature and RFC-3161 timestamp present in"
                " SignerInfo.unauthenticatedAttributes"
            )
        if "microsoft_time_stamp_token" in self.unauthenticated_attributes:
            ts_data = self.unauthenticated_attributes["microsoft_time_stamp_token"][0]
            if ts_data["content_type"].native != "signed_data":
                raise AuthenticodeParseError(
                    "RFC-3161 Timestamp does not contain SignedData structure"
                )

    @property
    def statement_types(self) -> list[str] | None:
        """Defines the key purpose of the signer. This is ignored by the
        verification.
        """
        if "microsoft_spc_statement_type" not in self.authenticated_attributes:
            return None
        return cast(
            list[str],
            self.authenticated_attributes["microsoft_spc_statement_type"][0].native,
        )

    @property
    def program_name(self) -> str | None:
        """This information is extracted from the SpcSpOpusInfo authenticated attribute,
        containing the program's name.
        """
        if "microsoft_spc_sp_opus_info" not in self.authenticated_attributes:
            return None
        return cast(
            str,
            self.authenticated_attributes["microsoft_spc_sp_opus_info"][0][
                "program_name"
            ].native,
        )

    @property
    def more_info(self) -> str | None:
        """This information is extracted from the SpcSpOpusInfo authenticated attribute,
        containing the URL with more information.
        """
        if "microsoft_spc_sp_opus_info" not in self.authenticated_attributes:
            return None
        return cast(
            str,
            self.authenticated_attributes["microsoft_spc_sp_opus_info"][0][
                "more_info"
            ].native,
        )

    @property
    def publisher_info(self) -> str | None:
        """This information is extracted from the SpcSpOpusInfo authenticated attribute,
        containing the publisher_info. It is almost never set, but is defined in the
        ASN.1 structure.
        """
        if "microsoft_spc_sp_opus_info" not in self.authenticated_attributes:
            return None
        return cast(
            str,
            self.authenticated_attributes["microsoft_spc_sp_opus_info"][0][
                "publisher_info"
            ].native,
        )

    @property
    def nested_signed_datas(self) -> list[AuthenticodeSignedData]:
        """It is possible for Authenticode SignerInfo objects to contain nested
        :class:`signify.pkcs7.SignedData` objects. This is  similar to including
        multiple SignedData structures in the
        :class:`signify.authenticode.AuthenticodeFile`.

        This field is extracted from the unauthenticated attributes.
        """
        if "microsoft_nested_signature" not in self.unauthenticated_attributes:
            return []

        result = []
        for sig_data in self.unauthenticated_attributes[
            "microsoft_nested_signature"
        ]:  # type: cms.SignedData
            content_type = sig_data["content_type"].native
            if content_type != "signed_data":
                raise AuthenticodeParseError(
                    "Nested signature is not a SignedData structure"
                )
            result.append(
                AuthenticodeSignedData(
                    sig_data["content"], signed_file=self.parent.signed_file
                )
            )

        return result

    @property
    def countersigner(self) -> AuthenticodeCounterSignerInfo | RFC3161SignedData | None:  # type: ignore[override]
        """Authenticode may use a different countersigning mechanism, rather than using
        a nested :class:`AuthenticodeCounterSignerInfo`, it may use a nested RFC-3161
        response, which is a nested :class:`signify.pkcs7.SignedData` structure
        (of type :class:`RFC3161SignedData`). This is also assigned to the countersigner
        attribute if this is available.
        """
        if "microsoft_time_stamp_token" in self.unauthenticated_attributes:
            ts_data = cast(
                cms.ContentInfo,
                self.unauthenticated_attributes["microsoft_time_stamp_token"][0],
            )
            return RFC3161SignedData(ts_data["content"])

        return cast("AuthenticodeCounterSignerInfo | None", super().countersigner)

    def _verify_issuer(
        self,
        issuer: Certificate,
        context: VerificationContext,
        signing_time: datetime.datetime | None = None,
    ) -> list[Certificate]:
        """Check whether the lifetime signing EKU is set. if that is the case, we can
        only use the timestamp for revocation checking, not for extending the lifetime
        of the signature. Revocation checking currently does not work.
        """
        if "microsoft_lifetime_signing" in issuer.extensions.get(
            "extended_key_usage", []
        ):
            signing_time = None
        return super()._verify_issuer(issuer, context, signing_time)


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
        and a zero hash (0000...).

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
        return cast(int, self.asn1["dwSIPversion"].native)

    @property
    def sip_guid(self) -> str:
        """The SIP GUID."""
        return cast(str, self.asn1["gSIPguid"].native)


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


class AuthenticodeSignedData(SignedData):
    """The :class:`signify.pkcs7.SignedData` structure for Authenticode. It holds the
    same information as its superclass, with additionally the :class:`IndirectData`.
    """

    signer_infos: Sequence[AuthenticodeSignerInfo]
    signer_info: AuthenticodeSignerInfo
    content_asn1: asn1.spc.SpcIndirectDataContent

    _expected_content_type = "microsoft_spc_indirect_data_content"
    _signerinfo_class = AuthenticodeSignerInfo

    def __init__(
        self,
        asn1: cms.SignedData,
        signed_file: signed_file.AuthenticodeFile | None = None,
    ):
        """
        :param asn1.pkcs7.SignedData asn1: The ASN.1 structure of the SignedData object
        :param signed_file: The related AuthenticodeFile.
        """
        self.signed_file = signed_file
        super().__init__(asn1)

    def _validate_asn1(self) -> None:
        super()._validate_asn1()
        if len(self.signer_infos) != 1:
            raise AuthenticodeParseError(
                "SignedData.signerInfos must contain exactly 1 signer,"
                f" not {len(self.signer_infos)}"
            )
        if self.asn1["crls"]:
            raise AuthenticodeParseError(
                "SignedData.crls is present, but that is unexpected."
            )

    @property
    def content(self) -> IndirectData:
        """The indirect data content of this :class:`AuthenticodeSignedData` object."""
        return IndirectData(self.content_asn1)

    @property
    def indirect_data(self) -> IndirectData:
        """Alias for :attr:`content`"""
        return self.content

    def iter_recursive_nested(self) -> Iterator[AuthenticodeSignedData]:
        """Returns an iterator over :class:`AuthenticodeSignedData` objects, including
        the current one, but also any nested :class:`AuthenticodeSignedData`
        objects in the :class:`AuthenticodeSignerInfo` structure.

        See :attr:`AuthenticodeSignerInfo.nested_signed_datas`
        """

        yield self
        for nested in self.signer_info.nested_signed_datas:
            yield from nested.iter_recursive_nested()

    def verify(  # type: ignore[override]
        self,
        verification_context: VerificationContext | None = None,
        *,
        expected_hash: bytes | None = None,
        verify_additional_hashes: bool = True,
        cs_verification_context: VerificationContext | None = None,
        trusted_certificate_store: CertificateStore = TRUSTED_CERTIFICATE_STORE,
        verification_context_kwargs: dict[str, Any] | None = None,
        countersignature_mode: Literal["strict", "permit", "ignore"] = "strict",
    ) -> Iterable[list[Certificate]]:
        """Verifies the SignedData structure, adds this to the base methods of
        :class:`SignedData`:

        * Verifies that the digest algorithms match across the structure
          (:class:`SpcInfo`, :class:`AuthenticodeSignedData` and
          :class:`AuthenticodeSignerInfo` must have the same)
        * Ensures that the hash in :attr:`SpcInfo.digest` matches the expected hash.
          If no expected hash is provided to this function, it is calculated using
          the :class:`Fingerprinter` obtained from the :class:`AuthenticodeFile` object.

        :param expected_hash: The expected hash digest of the
            :class:`AuthenticodeFile`.
        :param verify_additional_hashes: Defines whether additional hashes, should
            be verified, such as page hashes for PE files and extended digests for
            MSI files.
        :param verification_context: See :meth:`SignedData.verify`
        :param cs_verification_context: See :meth:`SignedData.verify`
        :param trusted_certificate_store: See :meth:`SignedData.verify`
        :param verification_context_kwargs: See :meth:`SignedData.verify`
        :param countersignature_mode: See :meth:`SignedData.verify`
        :raises AuthenticodeVerificationError: when the verification failed
        :return: A list of valid certificate chains for this SignedData.
        """

        # Check that the digest algorithms match
        if self.digest_algorithm != self.indirect_data.digest_algorithm:
            raise AuthenticodeInconsistentDigestAlgorithmError(
                "SignedData.digestAlgorithm must equal SpcInfo.digestAlgorithm"
            )

        if self.digest_algorithm != self.signer_info.digest_algorithm:
            raise AuthenticodeInconsistentDigestAlgorithmError(
                "SignedData.digestAlgorithm must equal SignerInfo.digestAlgorithm"
            )

        # Check that the hashes are correct
        # 1. The hash of the file
        if expected_hash is None:
            assert self.signed_file is not None
            expected_hash = self.signed_file.get_fingerprint(self.digest_algorithm)

        if expected_hash != self.indirect_data.digest:
            raise AuthenticodeInvalidDigestError(
                "The expected hash does not match the digest in SpcInfo"
            )

        if verify_additional_hashes and self.signed_file is not None:
            self.signed_file.verify_additional_hashes(self)

        try:
            return super().verify(
                verification_context=verification_context,
                cs_verification_context=cs_verification_context,
                trusted_certificate_store=(
                    trusted_certificate_store or TRUSTED_CERTIFICATE_STORE
                ),
                extended_key_usages=["code_signing"],
                verification_context_kwargs=verification_context_kwargs,
                countersignature_mode=countersignature_mode,
            )
        except InvalidDigestError as e:
            raise AuthenticodeInvalidDigestError(str(e))
        except CounterSignerError as e:
            raise AuthenticodeCounterSignerError(str(e))

    def explain_verify(
        self, *args: Any, **kwargs: Any
    ) -> tuple[AuthenticodeVerificationResult, Exception | None]:
        """This will return a value indicating the signature status of this object.
        This will not raise an error when the verification fails, but rather indicate
        this through the resulting enum

        :rtype: Tuple[AuthenticodeVerificationResult, Exception]
        :return: The verification result, and the exception containing more details
            (if available or None)
        """

        return AuthenticodeVerificationResult.call(self.verify, *args, **kwargs)


class RFC3161SignerInfo(SignerInfo):
    """Subclass of SignerInfo that is used to contain the signerinfo for the
    RFC3161SignedData option.
    """

    _expected_content_type = "tst_info"
    _countersigner_class = None  # prevent countersigners in here


class TSTInfo:
    """This is an implementation of the TSTInfo class as defined by RFC3161, used as
    content for a SignedData structure.
    """

    def __init__(self, asn1: tsp.TSTInfo):
        """
        :param asn1: The ASN.1 structure of the TSTInfo object
        """
        self.asn1 = asn1
        self._validate_asn1()

    def _validate_asn1(self) -> None:
        if self.asn1["version"].native != "v1":
            raise AuthenticodeParseError(
                f"TSTInfo.version must be v1, not {self.asn1['version'].native}"
            )

    @property
    def policy(self) -> str:
        """Policy attribute"""
        return cast(str, self.asn1["policy"].native)

    @property
    def hash_algorithm(self) -> HashFunction:
        """The hash algorithm of the message imprint."""
        return _get_digest_algorithm(
            self.asn1["message_imprint"]["hash_algorithm"],
            location="TSTInfo.messageImprint.hashAlgorithm",
        )

    @property
    def message_digest(self) -> bytes:
        """The hashed message"""
        return cast(bytes, self.asn1["message_imprint"]["hashed_message"].native)

    @property
    def serial_number(self) -> int:
        """The serial number of this signature"""
        return cast(int, self.asn1["serial_number"].native)

    @property
    def signing_time(self) -> datetime.datetime:
        """The time this signature was generated"""
        return cast(datetime.datetime, self.asn1["gen_time"].native)

    @property
    def signing_time_accuracy(self) -> datetime.timedelta | None:
        """The accuracy of the above time"""
        if self.asn1["accuracy"].native is None:
            return None
        return accuracy_to_python(self.asn1["accuracy"])

    @property
    def signing_time_ordering(self) -> bool:
        """Indicates whether the signing time can be ordered."""
        return cast("bool | None", self.asn1["ordering"].native) or False

    @property
    def signing_authority(self) -> CertificateName | None:
        """The authority generating this signature"""
        if self.asn1["tsa"].native is None:
            return None
        return CertificateName(self.asn1["tsa"])


class RFC3161SignedData(SignedData):
    """Some samples have shown to include a RFC-3161 countersignature in the
    unauthenticated attributes (as OID 1.3.6.1.4.1.311.3.3.1, which is in the Microsoft
    private namespace). This attribute contains its own signed data structure.

    This is a subclass of :class:`signify.pkcs7.SignedData`, containing a RFC3161
    TSTInfo in its content field.
    """

    content_asn1: tsp.TSTInfo
    _expected_content_type = "tst_info"
    _signerinfo_class = RFC3161SignerInfo

    def _validate_asn1(self) -> None:
        super()._validate_asn1()
        if len(self.signer_infos) != 1:
            raise AuthenticodeParseError(
                "RFC3161 SignedData.signerInfos must contain exactly 1 signer,"
                f" not {len(self.signer_infos)}"
            )

    @property
    def content(self) -> TSTInfo:
        """Contains the :class:`TSTInfo` class for this SignedData."""
        return TSTInfo(self.content_asn1)

    @property
    def tst_info(self) -> TSTInfo:
        """Alias for :attr:`content`."""
        return self.content

    @property
    def signing_time(self) -> datetime.datetime:
        """Transparent attribute to ensure that the signing_time attribute is
        consistently available.
        """
        return self.tst_info.signing_time

    def check_message_digest(self, data: bytes) -> bool:
        """Given the data, returns whether the hash_algorithm and message_digest match
        the data provided.
        """
        auth_attr_hasher = self.tst_info.hash_algorithm()
        auth_attr_hasher.update(data)
        return auth_attr_hasher.digest() == self.tst_info.message_digest

    def verify(  # type: ignore[override]
        self,
        verification_context: VerificationContext | None = None,
        *,
        trusted_certificate_store: CertificateStore | None = None,
        verification_context_kwargs: dict[str, Any] | None = None,
    ) -> Iterable[Iterable[Certificate]]:
        """Verifies the RFC3161 SignedData object. The context that is passed in must
        account for the certificate store of this object, or be left None.

        The object is verified by verifying that the hash of the :class:`TSTInfo`
        matches the :attr:`SignerInfo.message_digest` value. The remainder of the
        validation is done by calling :meth:`SignerInfo.verify`
        """

        # We should ensure that the hash in the SignerInfo matches the hash of the
        # content. This is similar to the normal verification process, where the
        # SpcInfo is verified. Note that the mapping between the RFC3161 SignedData
        # object is ensured by the verifier in SignedData

        return super().verify(
            verification_context=verification_context,
            trusted_certificate_store=trusted_certificate_store,
            verification_context_kwargs=verification_context_kwargs,
            extended_key_usages=["time_stamping"],
        )


if __name__ == "__main__":
    print(
        "This is a list of all certificates in the Authenticode trust store, ordered by"
        " expiration date"
    )
    for i, certificate in enumerate(
        sorted(TRUSTED_CERTIFICATE_STORE, key=lambda x: x.valid_to), start=1
    ):
        print(i, certificate.valid_to, certificate)
