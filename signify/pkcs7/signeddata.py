from __future__ import annotations

from typing import Any, Sequence, cast

from asn1crypto import cms
from asn1crypto.core import Asn1Value
from typing_extensions import Self

from signify._typing import HashFunction
from signify.asn1.hashing import _get_digest_algorithm
from signify.exceptions import ParseError
from signify.pkcs7 import signerinfo
from signify.x509.certificates import Certificate
from signify.x509.context import CertificateStore


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
    _signerinfo_class: type[signerinfo.SignerInfo] | str | None = None

    def __init__(self, asn1: cms.SignedData):
        """
        :param asn1: The ASN.1 structure of the SignedData object
        """

        if isinstance(self._signerinfo_class, str):
            self._signerinfo_class = globals()[self._signerinfo_class]

        self.asn1 = asn1
        self._validate_asn1()

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
        if len(self.asn1["digest_algorithms"]) != 1:
            raise ParseError(
                f"SignedData.digestAlgorithms must contain"
                f" exactly 1 algorithm, not {len(self.asn1['digestAlgorithms'])}"
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
    def signer_infos(self) -> Sequence[signerinfo.SignerInfo]:
        """A list of all included SignerInfo objects"""
        if self._signerinfo_class is not None:
            assert not isinstance(self._signerinfo_class, str)
            return [
                self._signerinfo_class(si, parent=self)
                for si in self.asn1["signer_infos"]
            ]
        else:
            raise AttributeError("No signer_infos expected")

    @property
    def signer_info(self) -> signerinfo.SignerInfo:
        if len(self.signer_infos) == 1:
            return self.signer_infos[0]
        raise AttributeError(
            "SignedData.signerInfos must contain exactly 1 signer,"
            f" not {len(self.signer_infos)}"
        )

    @property
    def content_digest(self) -> bytes:
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
