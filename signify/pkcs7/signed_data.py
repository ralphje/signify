from __future__ import annotations

import importlib
from collections.abc import Iterable, Sequence
from functools import cached_property
from typing import Any, Literal, cast

from asn1crypto import cms
from asn1crypto.core import Asn1Value
from typing_extensions import Self

from signify._typing import HashFunction
from signify.asn1.hashing import _get_digest_algorithm
from signify.exceptions import InvalidDigestError, ParseError
from signify.pkcs7 import signer_info
from signify.x509.certificates import Certificate
from signify.x509.context import CertificateStore, VerificationContext


class SignedData:
    """A generic SignedData object. The SignedData object is defined in RFC2315 and
    RFC5652 (amongst others) and defines data that is signed by one or more signers.

    It is based on the following ASN.1 object (as per RFC2315)::

        SignedData ::= SEQUENCE {
          version Version,
          digestAlgorithms DigestAlgorithmIdentifiers,
          contentInfo ContentInfo,
          certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
          crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
          signerInfos SignerInfos
        }

    In general, it describes some form of data, that is (obviously) signed. In the
    ASN.1 structure, you see the ``contentInfo``, which describes the signed content.
    (See :attr:`content_type` and :attr:`content_asn1`.

    Each :class:`SignedData` object may contain multiple signers. Information about
    these is found in :attr:`signer_infos`, pointing to one or more :class:`SignerInfo`
    classes.

    Additionally, :attr:`certificates` contains any additional (intermediate)
    certificates that may be required to verify these signers.
    """

    _expected_content_type: str | None = None
    _signerinfo_class_name: type[signer_info.SignerInfo] | str | None = None

    def __init__(self, asn1: cms.SignedData):
        """
        :param asn1: The ASN.1 structure of the SignedData object
        """
        self.asn1 = asn1
        self._validate_asn1()

    @cached_property
    def _signerinfo_class(self) -> type[signer_info.SignerInfo] | None:
        """Since the :attr:`_signerinfo_class_name` can be a string (since we may not
        be able to directly reference it at the place of definition), this method
        ensures that the appropriate subclass is loaded.
        """
        if isinstance(self._signerinfo_class_name, str):
            if "." in self._signerinfo_class_name:
                package_name, class_name = self._signerinfo_class_name.rsplit(".", 1)
                mod = importlib.import_module(package_name)
                return cast(type[signer_info.SignerInfo], getattr(mod, class_name))
            else:
                return cast(
                    type[signer_info.SignerInfo], globals()[self._signerinfo_class_name]
                )
        return self._signerinfo_class_name

    @classmethod
    def from_envelope(cls, data: bytes, *args: Any, **kwargs: Any) -> Self:
        """Loads a :class:`SignedData` object from raw data that contains ContentInfo.

        :param data: The bytes to parse
        """
        content_info = cms.ContentInfo.load(data)

        if content_info["content_type"].native != "signed_data":
            raise ParseError("ContentInfo does not contain SignedData")

        signed_data = cls(content_info["content"], *args, **kwargs)
        return signed_data

    def _validate_asn1(self) -> None:
        if len(self.asn1["digest_algorithms"]) > 1:
            raise ParseError(
                f"SignedData.digestAlgorithms must contain"
                f" exactly 1 algorithm, not {len(self.asn1['digest_algorithms'])}"
            )

        if self.content_type != self._expected_content_type:
            raise ParseError(
                f"SignedData.contentInfo contains {self.content_type},"
                f" expected {self._expected_content_type}"
            )

    @property
    def digest_algorithm(self) -> HashFunction:
        """The digest algorithm, i.e. the hash algorithm, that is used by the signers of
        the data.
        """
        if len(self.asn1["digest_algorithms"]) != 1:
            raise InvalidDigestError(
                "SignedData.digestAlgorithms does not contain any algorithms and is"
                " probably not signed."
            )

        return _get_digest_algorithm(
            self.asn1["digest_algorithms"][0], "SignedData.digestAlgorithm"
        )

    @property
    def content_type(self) -> str:
        """The class of the type of the content in the object."""
        return cast(str, self.asn1["encap_content_info"]["content_type"].native)

    @property
    def _real_content(self) -> Asn1Value:
        return self.asn1["encap_content_info"]["content"]

    @property
    def content_asn1(self) -> Asn1Value:
        """The actual content, as parsed by the :attr:`content_type` spec."""
        if hasattr(self._real_content, "parsed"):
            return self._real_content.parsed
        else:
            return self._real_content

    @property
    def certificates(self) -> CertificateStore:
        """A list of all included certificates in the SignedData. These can be used to
        determine a valid validation path from the signer to a root certificate.
        """
        return CertificateStore(
            [
                Certificate(cert)
                for cert in self.asn1["certificates"]
                if not isinstance(cert, cms.CertificateChoices)
                or cert.name == "certificate"
            ]
        )

    @property
    def signer_infos(self) -> Sequence[signer_info.SignerInfo]:
        """A list of all included :class:`signer_info.SignerInfo` objects"""
        if self._signerinfo_class is not None:
            return [
                self._signerinfo_class(si, parent=self)
                for si in self.asn1["signer_infos"]
            ]
        else:
            raise AttributeError("No signer_infos expected")

    @property
    def signer_info(self) -> signer_info.SignerInfo:
        """The included :class:`signer_info.SignerInfo` object, if there's one."""
        if len(self.signer_infos) == 1:
            return self.signer_infos[0]
        raise AttributeError(
            "SignedData.signerInfos must contain exactly 1 signer,"
            f" not {len(self.signer_infos)}"
        )

    def get_content_digest(self) -> bytes:
        """Returns the actual digest of the content of the SignedData object,
        adhering to the specs in RFC2315, 9.3; the identifier (tag) and
        length need to be stripped for hashing.
        """

        if hasattr(self._real_content, "parsed"):
            # Handle the case where the content is a ParsableOctetString, and
            # self.content.contents may refer to its children
            hash_content = bytes(self._real_content)
        else:
            hash_content = self.content_asn1.contents

        blob_hasher = self.digest_algorithm()
        blob_hasher.update(hash_content)
        return blob_hasher.digest()

    def _verify_message_digest(self) -> None:
        """Check that the message digest is correct.

        :raises InvalidDigestError: If the digest is invalid
        """
        if self.get_content_digest() != self.signer_info.message_digest:
            raise InvalidDigestError(
                "The expected hash of the content does not match SignerInfo"
            )

    def verify(
        self,
        verification_context: VerificationContext | None = None,
        *,
        cs_verification_context: VerificationContext | None = None,
        trusted_certificate_store: CertificateStore | None = None,
        extended_key_usages: list[str] | None = None,
        verification_context_kwargs: dict[str, Any] | None = None,
        countersignature_mode: Literal["strict", "permit", "ignore"] = "strict",
    ) -> Iterable[list[Certificate]]:
        """Verifies the SignedData structure:

        * Verifies that the content, when hashed, is the same as the value in
          :attr:`SignerInfo.message_digest`
        * In the case of a countersigner, calls :meth:`check_message_digest` on the
          countersigner to verify that the hashed value of
          :attr:`SignerInfo.encrypted_digest` is contained in the
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

        :param verification_context: The VerificationContext for
            verifying the chain of the :class:`SignerInfo`. The timestamp is overridden
            in the case of a countersigner. Default stores are
            ``trusted_certificate_store`` and the certificates of this
            :class:`SignedData` object. Required EKU is provided as
            ``extended_key_usages``
        :param cs_verification_context: The VerificationContext for
            verifying the chain of the :class:`CounterSignerInfo`. The timestamp is
            overridden in the case of a countersigner. Default stores are
            ``trusted_certificate_store`` and the certificates of this
            :class:`SignedData` object. Required EKU is ``time_stamping``.
        :param trusted_certificate_store: A :class:`CertificateStore`
            object that contains a list of trusted certificates to be used when
            :const:`None` is passed to either ``verification_context`` or
            ``cs_verification_context`` and a :class:`VerificationContext` is created.
        :param extended_key_usages: EKU's to check for in the verification context
            of this :class:`SignedData` object.
        :param dict verification_context_kwargs: If provided, keyword arguments that
            are passed to the instantiation of :class:`VerificationContext` s created
            in this function. Used for e.g. providing a timestamp.
        :param str countersignature_mode: Changes how countersignatures are handled.
            Defaults to 'strict', which means that errors in the countersignature
            result in verification failure. If set to 'permit', the countersignature is
            checked, but when it errors, it is verified as if the countersignature was
            never set. When set to 'ignore', countersignatures are never checked.
        :raises VerificationError: when the verification failed
        :return: A list of valid certificate chains for this SignedData.
        """

        self._verify_message_digest()

        if verification_context_kwargs is None:
            verification_context_kwargs = {}
        if trusted_certificate_store is None:
            trusted_certificate_store = CertificateStore()
        if verification_context is None:
            verification_context = VerificationContext(
                trusted_certificate_store,
                self.certificates,
                extended_key_usages=extended_key_usages,
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

        # Can't check authAttr hash against encrypted hash, done implicitly in
        # M2's pubkey.verify.

        return self.signer_info.verify(
            verification_context,
            countersigner_context=cs_verification_context,
            countersignature_mode=countersignature_mode,
        )
