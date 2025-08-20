from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, cast

from asn1crypto import cms

from signify.authenticode.tsp import RFC3161SignerInfoMixin
from signify.exceptions import AuthenticodeParseError
from signify.pkcs7 import CounterSignerInfo, SignerInfo
from signify.x509 import Certificate, VerificationContext

if TYPE_CHECKING:
    from signify.authenticode.signed_data import AuthenticodeSignature


class AuthenticodeCounterSignerInfo(CounterSignerInfo):
    """Subclass of :class:`CounterSignerInfo` that is used to contain the
    countersignerinfo for Authenticode.
    """


class AuthenticodeSignerInfo(RFC3161SignerInfoMixin, SignerInfo):
    """Subclass of :class:`SignerInfo` that is used by the verification of Authenticode.
    Note that this will contain the same attributes as :class:`SignerInfo`, with
    some additions.

    The :attr:`countersigner` attribute can hold the same as in the normal
    :class:`SignerInfo`, but may also contain a :class:`RFC3161SignedData` class.
    """

    parent: AuthenticodeSignature

    _singular_authenticated_attributes = (
        *SignerInfo._singular_authenticated_attributes,
        "microsoft_spc_statement_type",
        "microsoft_spc_sp_opus_info",
    )
    _singular_unauthenticated_attributes = (
        *SignerInfo._singular_unauthenticated_attributes,
        *RFC3161SignerInfoMixin._singular_unauthenticated_attributes,
    )
    _countersigner_class = AuthenticodeCounterSignerInfo
    _expected_content_type = "microsoft_spc_indirect_data_content"

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
    def nested_signed_datas(self) -> list[AuthenticodeSignature]:
        """It is possible for Authenticode SignerInfo objects to contain nested
        :class:`signify.pkcs7.SignedData` objects. This is  similar to including
        multiple SignedData structures in the
        :class:`signify.authenticode.AuthenticodeFile`.

        This field is extracted from the unauthenticated attributes.
        """
        from signify.authenticode.signed_data import AuthenticodeSignature

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
                AuthenticodeSignature(
                    sig_data["content"], signed_file=self.parent.signed_file
                )
            )

        return result

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
