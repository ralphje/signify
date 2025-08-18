from __future__ import annotations

import datetime
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, cast

from asn1crypto import cms, tsp

from signify._typing import HashFunction
from signify.asn1.hashing import _get_digest_algorithm
from signify.asn1.helpers import accuracy_to_python
from signify.exceptions import AuthenticodeParseError
from signify.pkcs7 import SignedData, SignerInfo
from signify.x509 import (
    Certificate,
    CertificateName,
    CertificateStore,
    VerificationContext,
)

if TYPE_CHECKING:
    from signify.authenticode.signer_info import (
        AuthenticodeCounterSignerInfo,
    )


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
    _signerinfo_class_name = RFC3161SignerInfo

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


if TYPE_CHECKING:
    _SignerInfoBase = SignerInfo
else:
    _SignerInfoBase = object


class RFC3161SignerInfoMixin(_SignerInfoBase):
    _singular_unauthenticated_attributes = (
        *SignerInfo._singular_unauthenticated_attributes,
        "microsoft_time_stamp_token",
    )

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
