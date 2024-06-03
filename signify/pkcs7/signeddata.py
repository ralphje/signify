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

    This class supports RFC2315 and RFC5652.

    .. attribute:: data

       The underlying ASN.1 data object

    .. attribute:: digest_algorithm

       The digest algorithm, i.e. the hash algorithm, that is used by the signers of
       the data.

    .. attribute:: content_type

       The class of the type of the content in the object.

    .. attribute:: content

       The actual content, as parsed by the :attr:`content_type` spec.

    .. attribute:: certificates
       :type: CertificateStore

       A list of all included certificates in the SignedData. These can be used to
       determine a valid validation path from the signer to a root certificate.

    .. attribute:: signer_infos
       :type: List[SignerInfo]

       A list of all included SignerInfo objects
    """

    data: cms.SignedData
    digest_algorithm: HashFunction
    content_type: str
    content: Asn1Value
    certificates: CertificateStore
    signer_infos: Sequence[signerinfo.SignerInfo]

    _expected_content_type: str | None = None
    _signerinfo_class: type[signerinfo.SignerInfo] | str | None = None

    def __init__(self, data: cms.SignedData):
        """

        :param data: The ASN.1 structure of the SignedData object
        """

        if isinstance(self._signerinfo_class, str):
            self._signerinfo_class = globals()[self._signerinfo_class]

        self.data = data
        self._parse()

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

    def _parse(self) -> None:
        #         ('version', CMSVersion),
        #         ('digest_algorithms', DigestAlgorithms),
        #         ('encap_content_info', None),
        #         ('certificates', CertificateSet, {'implicit': 0, 'optional': True}),
        #         ('crls', RevocationInfoChoices, {'implicit': 1, 'optional': True}),
        #         ('signer_infos', SignerInfos),

        # digestAlgorithms
        if len(self.data["digest_algorithms"]) != 1:
            raise ParseError(
                f"SignedData.digestAlgorithms must contain"
                f" exactly 1 algorithm, not {len(self.data['digestAlgorithms'])}"
            )
        self.digest_algorithm = _get_digest_algorithm(
            self.data["digest_algorithms"][0], "SignedData.digestAlgorithm"
        )

        self.content_type = self.data["encap_content_info"]["content_type"].native

        if self.content_type != self._expected_content_type:
            raise ParseError(
                f"SignedData.contentInfo contains {self.content_type},"
                f" expected {self._expected_content_type}"
            )

        self._real_content = self.data["encap_content_info"]["content"]
        if hasattr(self._real_content, "parsed"):
            self.content = self._real_content.parsed
        else:
            self.content = self._real_content

        # Certificates
        self.certificates = CertificateStore(
            [
                Certificate(cert)
                for cert in self.data["certificates"]
                if not isinstance(cert, cms.CertificateChoices)
                or cert.name == "certificate"
            ]
        )

        # SignerInfo
        if self._signerinfo_class is not None:
            assert not isinstance(self._signerinfo_class, str)
            self.signer_infos = [
                self._signerinfo_class(si, parent=self)
                for si in self.data["signer_infos"]
            ]

    @property
    def content_digest(self) -> bytes:
        """Returns the digest of the content of the SignedData object,
        adhering to the specs in RFC2315, 9.3; the identifier (tag) and
        length need to be stripped for hashing.
        """

        if hasattr(self._real_content, "parsed"):
            # Handle the case where the content is a ParsableOctetString, and
            # self.content.contents may refer to its children
            hash_content = bytes(self._real_content)
        else:
            hash_content = self.content.contents

        blob_hasher = self.digest_algorithm()
        blob_hasher.update(hash_content)
        return blob_hasher.digest()
