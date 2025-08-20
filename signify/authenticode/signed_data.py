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

from collections.abc import Iterable, Iterator, Sequence
from typing import TYPE_CHECKING, Any

from asn1crypto import cms
from typing_extensions import Literal

from signify import asn1
from signify.authenticode.cert_store import TRUSTED_CERTIFICATE_STORE
from signify.authenticode.indirect_data import IndirectData
from signify.authenticode.verification_result import AuthenticodeExplainVerifyMixin
from signify.exceptions import (
    AuthenticodeCounterSignerError,
    AuthenticodeFingerprintNotProvidedError,
    AuthenticodeInconsistentDigestAlgorithmError,
    AuthenticodeInvalidDigestError,
    AuthenticodeParseError,
    CounterSignerError,
    InvalidDigestError,
)
from signify.pkcs7 import SignedData
from signify.x509 import Certificate, CertificateStore, VerificationContext

if TYPE_CHECKING:
    from signify.authenticode import signed_file
    from signify.authenticode.signer_info import AuthenticodeSignerInfo


class AuthenticodeSignature(AuthenticodeExplainVerifyMixin, SignedData):
    """The :class:`signify.pkcs7.SignedData` structure for Authenticode. It holds the
    same information as its superclass, with additionally the :class:`IndirectData`.
    """

    signer_infos: Sequence[AuthenticodeSignerInfo]
    signer_info: AuthenticodeSignerInfo
    content_asn1: asn1.spc.SpcIndirectDataContent

    _expected_content_type = "microsoft_spc_indirect_data_content"
    _signerinfo_class_name = "signify.authenticode.signer_info.AuthenticodeSignerInfo"

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
        """The indirect data content of this :class:`AuthenticodeSignature` object."""
        return IndirectData(self.content_asn1)

    @property
    def indirect_data(self) -> IndirectData:
        """Alias for :attr:`content`"""
        return self.content

    def iter_recursive_nested(self) -> Iterator[AuthenticodeSignature]:
        """Returns an iterator over :class:`AuthenticodeSignature` objects, including
        the current one, but also any nested :class:`AuthenticodeSignature`
        objects in the :class:`AuthenticodeSignerInfo` structure.

        See :attr:`AuthenticodeSignerInfo.nested_signed_datas`
        """

        yield self
        for nested in self.signer_info.nested_signed_datas:
            yield from nested.iter_recursive_nested()

    def verify_indirect_data(
        self,
        indirect_data: IndirectData,
        *,
        expected_hash: bytes | None = None,
        verify_additional_hashes: bool = True,
    ) -> None:
        """Verifies the provided IndirectData against the expected hash.

        If a :attr:`signed_file` is available, this is relayed to
        :meth:`AuthenticodeSignedFile.verify_indirect_data`.

        If such file is not available, this simply checks whether the provided
        hash matches the hash in the :attr:`indirect_data`.

        :param expected_hash: The expected hash digest of the :class:`AuthenticodeFile`.
        :param verify_additional_hashes: Defines whether additional hashes, should
            be verified, such as page hashes for PE files and extended digests for
            MSI files.
        """
        if self.signed_file is not None:
            return self.signed_file.verify_indirect_data(
                indirect_data,
                expected_hash=expected_hash,
                verify_additional_hashes=verify_additional_hashes,
            )

        if expected_hash is None:
            raise AuthenticodeFingerprintNotProvidedError(
                f"Fingerprint for digest algorithm"
                f" {indirect_data.digest_algorithm.__name__} could not be calculated"
                " because no AuthenticodeSignedFile was provided, and the hash was not"
                " provided as pre-calculated expected hash."
            )

        # Check that the hashes are correct
        # 1. The hash of the file
        if expected_hash != indirect_data.digest:
            raise AuthenticodeInvalidDigestError(
                "The expected hash does not match the digest in the indirect data."
            )

        return None

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
          (:class:`SpcInfo`, :class:`AuthenticodeSignature` and
          :class:`AuthenticodeSignerInfo` must have the same)
        * Ensures that the hash in :attr:`SpcInfo.digest` matches the expected hash.
          If no expected hash is provided to this function, it is calculated using
          the :class:`Fingerprinter` obtained from the :class:`AuthenticodeFile` object.

        :param expected_hash: The expected hash digest of the :class:`AuthenticodeFile`.
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

        self.verify_indirect_data(
            self.indirect_data,
            expected_hash=expected_hash,
            verify_additional_hashes=verify_additional_hashes,
        )

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
