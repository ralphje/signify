from __future__ import annotations

import collections
import datetime
import logging
import re
from collections.abc import Iterable, Iterator
from functools import cached_property
from typing import Any, ClassVar, cast, overload

import asn1crypto.pem
import asn1crypto.x509
from asn1crypto import cms
from oscrypto import asymmetric

from signify import x509
from signify._typing import HashFunction
from signify.exceptions import CertificateVerificationError

logger = logging.getLogger(__name__)


AlgorithmIdentifier = collections.namedtuple(
    "AlgorithmIdentifier", "algorithm parameters"
)


class Certificate:
    """Representation of a Certificate. It is built from an ASN.1 structure."""

    asn1: asn1crypto.x509.Certificate

    def __init__(self, asn1: asn1crypto.x509.Certificate | cms.CertificateChoices):
        """
        :param asn1: The ASN.1 structure
        """

        self.asn1 = asn1

        if isinstance(self.asn1, cms.ExtendedCertificate):
            raise NotImplementedError(
                "Support for extendedCertificate is not implemented"
            )
        elif isinstance(self.asn1, cms.CertificateChoices):
            if self.asn1.name != "certificate":
                raise NotImplementedError(
                    f"This is not a certificate, but a {self.asn1.name}"
                )
            self.asn1 = self.asn1.chosen

    @property
    def signature_algorithm(self) -> str:
        """These values are considered part of the certificate, but not fully parsed."""
        return cast(str, self.asn1.signature_algo)

    @property
    def signature_value(self) -> bytes:
        """These values are considered part of the certificate, but not fully parsed."""
        return cast(bytes, self.asn1.signature)

    @property
    def version(self) -> str:
        """This is the version of the certificate"""
        return cast(str, self.asn1["tbs_certificate"]["version"].native)

    @property
    def serial_number(self) -> int:
        """The full integer serial number of the certificate"""
        return cast(int, self.asn1.serial_number)

    @property
    def issuer(self) -> CertificateName:
        """The :class:`CertificateName` for the issuer."""
        return CertificateName(self.asn1.issuer)

    @property
    def subject(self) -> CertificateName:
        """The :class:`CertificateName` for the subject."""
        return CertificateName(self.asn1.subject)

    @property
    def valid_from(self) -> datetime.datetime:
        """The datetime objects between which the certificate is valid."""
        return cast(datetime.datetime, self.asn1.not_valid_before)

    @property
    def valid_to(self) -> datetime.datetime:
        """The datetime objects between which the certificate is valid."""
        return cast(datetime.datetime, self.asn1.not_valid_after)

    @property
    def subject_public_algorithm(self) -> AlgorithmIdentifier:
        """These values are considered part of the certificate, but not fully parsed."""
        tbs_certificate = self.asn1["tbs_certificate"]
        return AlgorithmIdentifier(
            algorithm=tbs_certificate["subject_public_key_info"]["algorithm"][
                "algorithm"
            ].native,
            parameters=tbs_certificate["subject_public_key_info"]["algorithm"][
                "parameters"
            ].native,
        )

    @property
    def subject_public_key(self) -> bytes:
        """These values are considered part of the certificate, but not fully parsed."""
        return cast(
            bytes,
            self.asn1["tbs_certificate"]["subject_public_key_info"][
                "public_key"
            ].dump(),
        )

    @property
    def extensions(self) -> dict[str, Any]:
        """This is a list of extension objects."""
        result = {}
        tbs_certificate = self.asn1["tbs_certificate"]
        if tbs_certificate["extensions"].native is not None:
            for extension in tbs_certificate["extensions"]:
                result[extension["extn_id"].native] = extension["extn_value"].native
        return result

    def __str__(self) -> str:
        return (
            f"{self.subject.dn}"
            f" (serial:{self.serial_number}, sha1:{self.sha1_fingerprint})"
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.issuer,
                self.serial_number,
                self.subject,
                self.subject_public_algorithm,
                self.subject_public_key,
            )
        )

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Certificate)
            and self.issuer == other.issuer
            and self.serial_number == other.serial_number
            and self.subject == other.subject
            and self.subject_public_algorithm == other.subject_public_algorithm
            and self.subject_public_key == other.subject_public_key
        )

    @classmethod
    def from_der(cls, content: bytes) -> Certificate:
        """Load the Certificate object from DER-encoded data"""
        return cls(asn1crypto.x509.Certificate.load(content))

    @classmethod
    def from_pem(cls, content: bytes) -> Certificate:
        """Reads a Certificate from a PEM formatted file."""
        return next(cls.from_pems(content))

    @classmethod
    def from_pems(cls, content: bytes) -> Iterator[Certificate]:
        """Reads a Certificate from a PEM formatted file."""
        for _type_name, _headers, der_bytes in asn1crypto.pem.unarmor(
            content, multiple=True
        ):
            yield cls.from_der(der_bytes)

    @cached_property
    def to_der(self) -> bytes:
        """Returns the DER-encoded data from this certificate."""
        return cast(bytes, self.asn1.dump())

    @cached_property
    def sha256_fingerprint(self) -> str:
        return cast(str, self.asn1.sha256_fingerprint).replace(" ", "").lower()

    @cached_property
    def sha1_fingerprint(self) -> str:
        return cast(str, self.asn1.sha1_fingerprint).replace(" ", "").lower()

    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
        algorithm: HashFunction,
        allow_legacy: bool = False,
    ) -> None:
        """Verifies whether the signature bytes match the data using the hashing
        algorithm. Supports RSA and EC keys. Note that not all hashing algorithms
        are supported.

        :param bytes signature: The signature to verify
        :param bytes data: The data that must be verified
        :type algorithm: a hashlib function
        :param algorithm: The hashing algorithm to use
        :param bool allow_legacy: If True, allows a legacy signature verification.
            This method is intended for the case where the encryptedDigest does not
            contain an ASN.1 structure, but a raw hash value instead. It is attempted
            automatically when verification of the RSA signature fails.

            This case is described in more detail on
            https://mta.openssl.org/pipermail/openssl-users/2015-September/002053.html
        """

        public_key = asymmetric.load_public_key(self.asn1.public_key)
        if public_key.algorithm == "rsa":
            verify_func = asymmetric.rsa_pkcs1v15_verify
        elif public_key.algorithm == "dsa":
            verify_func = asymmetric.dsa_verify
        elif public_key.algorithm == "ec":
            verify_func = asymmetric.ecdsa_verify
        else:
            raise CertificateVerificationError(
                f"Signature algorithm {public_key.algorithm} is unsupported for {self}"
            )

        try:
            verify_func(public_key, signature, data, algorithm().name)
        except Exception as e:
            if not allow_legacy or public_key.algorithm != "rsa":
                raise CertificateVerificationError(f"Invalid signature for {self}: {e}")
        else:
            return

        try:
            hasher = algorithm()
            hasher.update(data)
            asymmetric.rsa_pkcs1v15_verify(
                public_key, signature, hasher.digest(), "raw"
            )
        except Exception as e:
            raise CertificateVerificationError(
                f"Invalid signature for {self} (legacy attempted): {e}"
            )

    def potential_chains(
        self, context: x509.VerificationContext
    ) -> Iterator[list[Certificate]]:
        """Alias for :meth:`VerificationContext.potential_chains`"""

        return context.potential_chains(self)

    def verify(self, context: x509.VerificationContext) -> Iterable[Certificate]:
        """Alias for :meth:`VerificationContext.verify`"""

        return context.verify(self)


class CertificateName:
    # References: https://github.com/lief-project/LIEF/blob/c678f6bdfb3f3199b36e1f8df25f7432a2725f53/src/PE/signature/OIDToString.cpp
    # Reference: https://cryptography.io/en/latest/x509/reference/
    OID_TO_RDN: ClassVar[dict[str, str]] = {
        "2.5.4.3": "CN",  # common name
        "2.5.4.5": "Serial",  # serialNumber
        "2.5.4.6": "C",  # country
        "2.5.4.7": "L",  # locality
        "2.5.4.8": "ST",  # stateOrProvince
        "2.5.4.9": "STREET",  # street
        "2.5.4.10": "O",  # organization
        "2.5.4.11": "OU",  # organizationalUnit
        "2.5.4.15": "Business Category",  # businessCategory
        "2.5.4.17": "Postal Code",  # postalCode
        "1.3.6.1.4.1.311.60.2.1.3": "Jurisdiction Country",  # jurisdictionCountry
        "0.9.2342.19200300.100.1.25": "DC",  # domainComponent
        "1.2.840.113549.1.9.1": "EMAIL",  # emailaddress
    }

    def __init__(self, asn1: asn1crypto.x509.Name | asn1crypto.x509.GeneralName):
        if isinstance(asn1, asn1crypto.x509.GeneralName):
            if asn1.name != "directory_name":
                raise NotImplementedError(
                    f"CertificateNames of type {asn1.name} not supported"
                )
            asn1 = asn1.chosen
        self.asn1 = asn1

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CertificateName) and self.rdns == other.rdns

    def __hash__(self) -> int:
        return hash(self.rdns)

    def __str__(self) -> str:
        return self.dn

    @property
    def dn(self) -> str:
        """Returns an (almost) rfc2253 compatible string given a RDNSequence"""

        result = []
        for type, value in self.get_components():
            #   If the AttributeType is in a published table of attribute types
            #   associated with LDAP [4], then the type name string from that table
            #   is used, otherwise it is encoded as the dotted-decimal encoding of
            #   the AttributeType's OBJECT IDENTIFIER.

            # Escaping according to RFC2253
            value = re.sub('([,+"<>;\\\\])', r"\\\1", value)
            if value.startswith("#"):
                value = "\\" + value
            if value.endswith(" "):
                value = value[:-1] + "\\ "
            result.append(f"{type}={value}")
        return ", ".join(result)

    @property
    def rdns(self) -> Iterable[tuple[str, str]]:
        """A list of all components of the object."""
        return tuple(self.get_components())

    @overload
    def get_components(
        self, component_type: None = None
    ) -> Iterator[tuple[str, str]]: ...

    @overload
    def get_components(self, component_type: str) -> Iterator[str]: ...

    def get_components(
        self, component_type: str | None = None
    ) -> Iterator[tuple[str, str]] | Iterator[str]:
        """Get individual components of this CertificateName

        :param component_type: if provided, yields only values of this type,
            if not provided, yields tuples of (type, value)
        """

        for n in list(self.asn1.chosen)[::-1]:
            type_value = n[0]  # get the AttributeTypeAndValue object

            type = self.OID_TO_RDN.get(
                type_value["type"].dotted, type_value["type"].dotted
            )
            value = type_value["value"].native

            if component_type is not None:
                if component_type in (
                    type_value["type"].dotted,
                    type_value["type"].native,
                    type,
                ):
                    yield value
            else:
                yield type, value
