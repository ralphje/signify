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
import logging
import pathlib
from typing import Any, Callable, Iterable, Sequence

import mscerts
from asn1crypto import cms, tsp
from typing_extensions import Literal, ParamSpec

from signify import asn1
from signify._typing import HashFunction
from signify.asn1 import spc
from signify.asn1.hashing import _get_digest_algorithm
from signify.asn1.helpers import accuracy_to_python
from signify.authenticode import signed_pe
from signify.authenticode.authroot import CertificateTrustList
from signify.exceptions import (
    AuthenticodeCounterSignerError,
    AuthenticodeInconsistentDigestAlgorithmError,
    AuthenticodeInvalidDigestError,
    AuthenticodeNotSignedError,
    AuthenticodeParseError,
    CertificateVerificationError,
    ParseError,
    SignedPEParseError,
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

    @classmethod
    def call(
        cls, function: Callable[_P, Any], *args: _P.args, **kwargs: _P.kwargs
    ) -> tuple[AuthenticodeVerificationResult, Exception | None]:
        try:
            function(*args, **kwargs)
        except (SignedPEParseError, AuthenticodeNotSignedError) as exc:
            return cls.NOT_SIGNED, exc
        except AuthenticodeInconsistentDigestAlgorithmError as exc:
            return cls.INCONSISTENT_DIGEST_ALGORITHM, exc
        except AuthenticodeInvalidDigestError as exc:
            return cls.INVALID_DIGEST, exc
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
    Note that this will contain the same attributes as :class:`SignerInfo`, and
    additionally the following:

    .. attribute:: program_name
                   more_info
                   publisher_info

       This information is extracted from the SpcSpOpusInfo authenticated attribute,
       containing the program's name and an URL with more information. The
       publisher_info is almost never set, but is defined in the ASN.1 structure.

    .. attribute:: statement_types

       Defines the key purpose of the signer. This is ignored by the verification.

    .. attribute:: nested_signed_datas

       It is possible for Authenticode SignerInfo objects to contain nested
       :class:`signify.pkcs7.SignedData` objects. This is  similar to including
       multiple SignedData structures in the :class:`signify.authenticode.SignedPEFile`.
       This field  is extracted from  the unauthenticated attributes.

    The :attr:`countersigner` attribute can hold the same as in the normal
    :class:`SignerInfo`, but may also contain a :class:`RFC3161SignedData` class:

    .. attribute:: countersigner

       Authenticode may use a different countersigning mechanism, rather than using a
       nested :class:`AuthenticodeCounterSignerInfo`, it  may use a nested RFC-3161
       response, which is a nested :class:`signify.pkcs7.SignedData` structure
       (of type :class:`RFC3161SignedData`). This is also assigned to the countersigner
       attribute if this is available.


    """

    program_name: str | None
    more_info: str | None
    publisher_info: str | None
    nested_signed_datas: list[AuthenticodeSignedData]

    parent: AuthenticodeSignedData
    # allow other countersigner as well
    countersigner: (  # type: ignore[assignment]
        AuthenticodeCounterSignerInfo | RFC3161SignedData | None
    )

    _countersigner_class = AuthenticodeCounterSignerInfo
    _expected_content_type = "microsoft_spc_indirect_data_content"

    def _parse(self) -> None:
        super()._parse()

        # - Retrieve statement types
        self.statement_types = None
        if "microsoft_spc_statement_type" in self.authenticated_attributes:
            if len(self.authenticated_attributes["microsoft_spc_statement_type"]) != 1:
                raise AuthenticodeParseError(
                    "Only one SpcStatementType expected in"
                    " SignerInfo.authenticatedAttributes"
                )
            self.statement_types = self.authenticated_attributes[
                "microsoft_spc_statement_type"
            ][0].native

        # - Retrieve object from SpcSpOpusInfo from the authenticated attributes
        # (for normal signer)
        self.program_name = self.more_info = self.publisher_info = None
        if "microsoft_spc_sp_opus_info" in self.authenticated_attributes:
            if len(self.authenticated_attributes["microsoft_spc_sp_opus_info"]) != 1:
                raise AuthenticodeParseError(
                    "Only one SpcSpOpusInfo expected in"
                    " SignerInfo.authenticatedAttributes"
                )

            self.program_name = self.authenticated_attributes[
                "microsoft_spc_sp_opus_info"
            ][0]["program_name"].native
            self.more_info = self.authenticated_attributes[
                "microsoft_spc_sp_opus_info"
            ][0]["more_info"].native
            self.publisher_info = self.authenticated_attributes[
                "microsoft_spc_sp_opus_info"
            ][0]["publisher_info"].native

        # - Authenticode can use nested signatures through OID 1.3.6.1.4.1.311.2.4.1
        self.nested_signed_datas = []
        if "microsoft_nested_signature" in self.unauthenticated_attributes:
            for sig_data in self.unauthenticated_attributes[
                "microsoft_nested_signature"
            ]:
                content_type = sig_data["content_type"].native
                if content_type != "signed_data":
                    raise AuthenticodeParseError(
                        "Nested signature is not a SignedData structure"
                    )
                self.nested_signed_datas.append(
                    AuthenticodeSignedData(
                        sig_data["content"], pefile=self.parent.pefile
                    )
                )

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
            if len(self.unauthenticated_attributes["microsoft_time_stamp_token"]) != 1:
                raise AuthenticodeParseError(
                    "Only one RFC-3161 timestamp expected in"
                    " SignerInfo.unauthenticatedAttributes"
                )

            ts_data = self.unauthenticated_attributes["microsoft_time_stamp_token"][0]
            if ts_data["content_type"].native != "signed_data":
                raise AuthenticodeParseError(
                    "RFC-3161 Timestamp does not contain SignedData structure"
                )

            self.countersigner = RFC3161SignedData(ts_data["content"])

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


class SpcInfo:
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
        DigestInfo ::= SEQUENCE {
            digestAlgorithm  AlgorithmIdentifier,
            digest OCTETSTRING
        }
        AlgorithmIdentifier ::= SEQUENCE {
            algorithm ObjectID,
            parameters [0] EXPLICIT ANY OPTIONAL
        }

    .. attribute:: data

       The underlying ASN.1 data object

    .. attribute:: content_type

       The contenttype string

    .. attribute:: image_data

       The image data object embedded in the ASN.1 object.

    .. attribute:: image_flags

       The flags used for signing. These flags are ignored during verification.

    .. attribute:: image_publisher

       Obsolete software publisher field (i.e. ``SpcPeImageData.file``). Should now
       contain ``<<<Obsolete>>>``, although this value does not affect verification.

    .. attribute:: digest_algorithm
    .. attribute:: digest


    """

    data: spc.SpcIndirectDataContent

    content_type: str
    image_data: spc.SpcPeImageData
    image_flags: set[str]
    image_publisher: str
    digest_algorithm: HashFunction
    digest: bytes

    def __init__(self, data: spc.SpcIndirectDataContent):
        self.data = data
        self._parse()

    def _parse(self) -> None:
        # The data attribute
        self.content_type = self.data["data"]["type"].native

        if self.content_type != "microsoft_spc_pe_image_data":
            raise AuthenticodeParseError("SpcInfo does not contain SpcPeImageData")

        self.image_data = self.data["data"]["value"]
        self.image_flags = self.image_data["flags"].native
        self.image_publisher = self.image_data["file"].native

        self.digest_algorithm = _get_digest_algorithm(
            self.data["message_digest"]["digest_algorithm"],
            location="SpcIndirectDataContent.digestAlgorithm",
        )
        self.digest = self.data["message_digest"]["digest"].native


class AuthenticodeSignedData(SignedData):
    """The :class:`signify.pkcs7.SignedData` structure for Authenticode. It holds the
    same information as its superclass, with additionally the :class:`SpcInfo`:

    .. attribute:: spc_info

       The parsed :attr:`content` of this :class:`SignedData` object, being a
       SpcIndirectDataContent object.

    """

    pefile: signed_pe.SignedPEFile | None
    spc_info: SpcInfo
    signer_infos: Sequence[AuthenticodeSignerInfo]
    signer_info: AuthenticodeSignerInfo

    content: asn1.spc.SpcIndirectDataContent
    _expected_content_type = "microsoft_spc_indirect_data_content"
    _signerinfo_class = AuthenticodeSignerInfo

    def __init__(
        self,
        data: cms.SignedData,
        pefile: signed_pe.SignedPEFile | None = None,
    ):
        """
        :param asn1.pkcs7.SignedData data: The ASN.1 structure of the SignedData object
        :param pefile: The related PEFile.
        """
        self.pefile = pefile
        super().__init__(data)

    def _parse(self) -> None:
        super()._parse()
        self.spc_info = SpcInfo(self.content)

        # signerInfos
        if len(self.signer_infos) != 1:
            raise AuthenticodeParseError(
                "SignedData.signerInfos must contain exactly 1 signer,"
                f" not {len(self.signer_infos)}"
            )

        self.signer_info = self.signer_infos[0]

        # CRLs
        if self.data["crls"]:
            raise AuthenticodeParseError(
                "SignedData.crls is present, but that is unexpected."
            )

    def verify(
        self,
        *,
        expected_hash: bytes | None = None,
        verification_context: VerificationContext | None = None,
        cs_verification_context: VerificationContext | None = None,
        trusted_certificate_store: CertificateStore = TRUSTED_CERTIFICATE_STORE,
        verification_context_kwargs: dict[str, Any] | None = None,
        countersignature_mode: Literal["strict", "permit", "ignore"] = "strict",
    ) -> Iterable[list[Certificate]]:
        """Verifies the SignedData structure:

        * Verifies that the digest algorithms match across the structure
          (:class:`SpcInfo`, :class:`AuthenticodeSignedData` and
          :class:`AuthenticodeSignerInfo` must have the same)
        * Ensures that the hash in :attr:`SpcInfo.digest` matches the expected hash.
          If no expected hash is provided to this function, it is calculated using
          the :class:`Fingerprinter` obtained from the :class:`SignedPEFile` object.
        * Verifies that the :class:`SpcInfo`, when hashed, is the same as the value in
          :attr:`SignerInfo.message_digest`
        * In the case of a countersigner, calls :meth:`check_message_digest` on the
          countersigner to verify that the hashed value of
          :attr:`AuthenticodeSignerInfo.encrypted_digest` is contained in the
          countersigner.
        * Verifies the chain of the countersigner up to a trusted root, see
          :meth:`SignerInfo.verify` and :meth:`RFC3161SignedData.verify`
        * Verifies the chain of the signer up to a trusted root, see
          :meth:`SignerInfo.verify`

        In the case of a countersigner, the verification is performed using the
        timestamp of the :class:`CounterSignerInfo`, otherwise now is assumed. If there
        is no countersigner, you can override this by specifying a different timestamp
        in the :class:`VerificationContext`. Note that you cannot set a timestamp when
        checking against the CRL; this is not permitted by the underlying library. If
        you need to do this, you must therefore set countersignature_mode to ``ignore``.

        :param bytes expected_hash: The expected hash digest of the
            :class:`SignedPEFile`.
        :param VerificationContext verification_context: The VerificationContext for
            verifying the chain of the :class:`SignerInfo`. The timestamp is overridden
            in the case of a countersigner. Default stores are TRUSTED_CERTIFICATE_STORE
            and the certificates of this :class:`SignedData` object. EKU is code_signing
        :param VerificationContext cs_verification_context: The VerificationContext for
            verifying the chain of the :class:`CounterSignerInfo`. The timestamp is
            overridden in the case of a countersigner. Default stores are
            TRUSTED_CERTIFICATE_STORE and the certificates of this :class:`SignedData`
            object. EKU is time_stamping
        :param CertificateStore trusted_certificate_store: A :class:`CertificateStore`
            object that contains a list of trusted certificates to be used when
            :const:`None` is passed to either ``verification_context`` or
            ``cs_verification_context`` and a :class:`VerificationContext` is created.
        :param dict verification_context_kwargs: If provided, keyword arguments that
            are passed to the instantiation of :class:`VerificationContext` s created
            in this function. Used for e.g. providing a timestamp.
        :param str countersignature_mode: Changes how countersignatures are handled.
            Defaults to 'strict', which means that errors in the countersignature
            result in verification failure. If set to 'permit', the countersignature is
            checked, but when it errors, it is verified as if the countersignature was
            never set. When set to 'ignore', countersignatures are never checked.
        :raises AuthenticodeVerificationError: when the verification failed
        :return: A list of valid certificate chains for this SignedData.
        """

        if verification_context_kwargs is None:
            verification_context_kwargs = {}
        if verification_context is None:
            verification_context = VerificationContext(
                trusted_certificate_store,
                self.certificates,
                extended_key_usages=["code_signing"],
                **verification_context_kwargs,
            )

        if (
            cs_verification_context is None
            and self.signer_info.countersigner
            and countersignature_mode != "ignore"
        ):
            cs_verification_context = VerificationContext(
                trusted_certificate_store,
                self.certificates,
                extended_key_usages=["time_stamping"],
                **verification_context_kwargs,
            )
            # Add the local certificate store for the countersignature
            # (in the case of RFC3161SignedData)
            if hasattr(self.signer_info.countersigner, "certificates"):
                cs_verification_context.add_store(
                    self.signer_info.countersigner.certificates
                )

        # Check that the digest algorithms match
        if self.digest_algorithm != self.spc_info.digest_algorithm:
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
            assert self.pefile is not None
            fingerprinter = self.pefile.get_fingerprinter()
            fingerprinter.add_authenticode_hashers(self.digest_algorithm)
            expected_hash = fingerprinter.hash()[self.digest_algorithm().name]

        if expected_hash != self.spc_info.digest:
            raise AuthenticodeInvalidDigestError(
                "The expected hash does not match the digest in SpcInfo"
            )

        # 2. The hash of the spc blob
        if self.content_digest != self.signer_info.message_digest:
            raise AuthenticodeInvalidDigestError(
                "The expected hash of the SpcInfo does not match SignerInfo"
            )

        # Can't check authAttr hash against encrypted hash, done implicitly in
        # M2's pubkey.verify.

        signing_time = None
        if self.signer_info.countersigner and countersignature_mode != "ignore":
            assert cs_verification_context is not None

            try:
                # 3. Check the countersigner hash.
                # Make sure to use the same digest_algorithm that the countersigner used
                if not self.signer_info.countersigner.check_message_digest(
                    self.signer_info.encrypted_digest
                ):
                    raise AuthenticodeCounterSignerError(
                        "The expected hash of the encryptedDigest does not match"
                        " countersigner's SignerInfo"
                    )

                cs_verification_context.timestamp = (
                    self.signer_info.countersigner.signing_time
                )

                # We could be calling SignerInfo.verify or RFC3161SignedData.verify
                # here, but those have identical signatures. Note that
                # RFC3161SignedData accepts a trusted_certificate_store argument, but
                # we pass in an explicit context anyway
                self.signer_info.countersigner.verify(cs_verification_context)
            except Exception as e:
                if countersignature_mode != "strict":
                    pass
                else:
                    raise AuthenticodeCounterSignerError(
                        f"An error occurred while validating the countersignature: {e}"
                    )
            else:
                # If no errors occur, we should be fine setting the timestamp to the
                # countersignature's timestamp
                signing_time = self.signer_info.countersigner.signing_time

        return self.signer_info.verify(verification_context, signing_time)

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
    content for a SignedData structure. The following properties are available:

    .. attribute:: data

       The underlying ASN.1 data object

    .. attribute:: policy

    .. attribute:: hash_algorithm

       The hash algorithm of the message imprint.

    .. attribute:: message_digest

       The hashed message

    .. attribute:: serial_number

       The serial number of this signature

    .. attribute:: signing_time

       The time this signature was generated

    .. attribute:: signing_time_accuracy

       The accuracy of the above time

    .. attribute:: signing_authority

       The authority generating this signature

    """

    policy: str
    hash_algorithm: HashFunction
    message_digest: bytes
    serial_number: int
    signing_time: datetime.datetime
    signing_time_accuracy: datetime.timedelta
    signing_authority: CertificateName

    def __init__(self, data: tsp.TSTInfo):
        """

        :param data: The ASN.1 structure of the TSTInfo object
        """
        self.data = data
        self._parse()

    def _parse(self) -> None:
        if self.data["version"].native != "v1":
            raise AuthenticodeParseError(
                f"TSTInfo.version must be v1, not {self.data['version'].native}"
            )

        self.policy = self.data["policy"].native
        self.hash_algorithm = _get_digest_algorithm(
            self.data["message_imprint"]["hash_algorithm"],
            location="TSTInfo.messageImprint.hashAlgorithm",
        )
        self.message_digest = self.data["message_imprint"]["hashed_message"].native
        self.serial_number = self.data["serial_number"].native
        self.signing_time = self.data["gen_time"].native
        self.signing_time_accuracy = accuracy_to_python(self.data["accuracy"])
        self.signing_authority = CertificateName(self.data["tsa"])


class RFC3161SignedData(SignedData):
    """Some samples have shown to include a RFC-3161 countersignature in the
    unauthenticated attributes (as OID 1.3.6.1.4.1.311.3.3.1, which is in the Microsoft
    private namespace). This attribute contains its own signed data structure.

    This is a subclass of :class:`signify.pkcs7.SignedData`, containing a RFC3161
    TSTInfo in its content field.

    .. attribute:: tst_info
       :type: TSTInfo

       Contains the :class:`TSTInfo` class for this SignedData.
    """

    content: tsp.TSTInfo
    _expected_content_type = "tst_info"
    _signerinfo_class = RFC3161SignerInfo

    def _parse(self) -> None:
        super()._parse()

        # Get the tst_info
        self.tst_info = TSTInfo(self.content)

        # signerInfos
        if len(self.signer_infos) != 1:
            raise AuthenticodeParseError(
                "RFC3161 SignedData.signerInfos must contain exactly 1 signer,"
                f" not {len(self.signer_infos)}"
            )

        self.signer_info = self.signer_infos[0]

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

    def verify(
        self,
        context: VerificationContext | None = None,
        *,
        trusted_certificate_store: CertificateStore = TRUSTED_CERTIFICATE_STORE,
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
        if self.content_digest != self.signer_info.message_digest:
            raise AuthenticodeCounterSignerError(
                "The expected hash of the TstInfo does not match SignerInfo"
            )

        if context is None:
            context = VerificationContext(
                trusted_certificate_store,
                self.certificates,
                extended_key_usages=["time_stamping"],
            )

        # The context is set correctly by the 'verify' function, including the current
        # certificate store
        return self.signer_info.verify(context)


if __name__ == "__main__":
    print(
        "This is a list of all certificates in the Authenticode trust store, ordered by"
        " expiration date"
    )
    for i, certificate in enumerate(
        sorted(TRUSTED_CERTIFICATE_STORE, key=lambda x: x.valid_to), start=1
    ):
        print(i, certificate.valid_to, certificate)
