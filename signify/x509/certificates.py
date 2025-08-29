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
    """Representation of a certificate. It is built from an ASN.1 structure."""

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

        :param signature: The signature to verify
        :param data: The data that must be verified
        :param algorithm: The hashing algorithm to use
        :param allow_legacy: If :const:`True`, allows legacy signature verification.
            This method is intended for the case where the ``signature`` does not
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
    OID_TO_RDN: ClassVar[dict[str, str]] = {
        # The following list is based on RFC4514
        "2.5.4.3": "CN",  # commonName
        "2.5.4.6": "C",  # countryName
        "2.5.4.7": "L",  # localityName
        "2.5.4.8": "ST",  # stateOrProvinceName
        "2.5.4.9": "STREET",  # street (uppercase in RFC4514, but lowercase in OpenSSL)
        "2.5.4.10": "O",  # organizationName
        "2.5.4.11": "OU",  # organizationalUnitName
        "0.9.2342.19200300.100.1.25": "DC",  # domainComponent
        "1.2.840.113549.1.9.1": "EMAIL",  # emailAddress (shortcut not in OpenSSL)
        # The remainder of this list is based on the OIDs present in OpenSSL
        # See https://github.com/openssl/openssl/blob/master/crypto/objects/objects.txt
        # Note that the official list is with IANA at
        # https://www.iana.org/assignments/ldap-parameters/ldap-parameters.xhtml#ldap-parameters-3
        "0.9.2342.19200300.100.1.1": "UID",
        "0.9.2342.19200300.100.1.2": "textEncodedORAddress",
        "0.9.2342.19200300.100.1.3": "mail",
        "0.9.2342.19200300.100.1.4": "info",
        "0.9.2342.19200300.100.1.5": "favouriteDrink",
        "0.9.2342.19200300.100.1.6": "roomNumber",
        "0.9.2342.19200300.100.1.7": "photo",
        "0.9.2342.19200300.100.1.8": "userClass",
        "0.9.2342.19200300.100.1.9": "host",
        "0.9.2342.19200300.100.1.10": "manager",
        "0.9.2342.19200300.100.1.11": "documentIdentifier",
        "0.9.2342.19200300.100.1.12": "documentTitle",
        "0.9.2342.19200300.100.1.13": "documentVersion",
        "0.9.2342.19200300.100.1.14": "documentAuthor",
        "0.9.2342.19200300.100.1.15": "documentLocation",
        "0.9.2342.19200300.100.1.20": "homeTelephoneNumber",
        "0.9.2342.19200300.100.1.21": "secretary",
        "0.9.2342.19200300.100.1.22": "otherMailbox",
        "0.9.2342.19200300.100.1.23": "lastModifiedTime",
        "0.9.2342.19200300.100.1.24": "lastModifiedBy",
        "0.9.2342.19200300.100.1.26": "aRecord",
        "0.9.2342.19200300.100.1.28": "mXRecord",
        "0.9.2342.19200300.100.1.29": "nSRecord",
        "0.9.2342.19200300.100.1.30": "sOARecord",
        "0.9.2342.19200300.100.1.31": "cNAMERecord",
        "0.9.2342.19200300.100.1.37": "associatedDomain",
        "0.9.2342.19200300.100.1.38": "associatedName",
        "0.9.2342.19200300.100.1.39": "homePostalAddress",
        "0.9.2342.19200300.100.1.40": "personalTitle",
        "0.9.2342.19200300.100.1.41": "mobileTelephoneNumber",
        "0.9.2342.19200300.100.1.42": "pagerTelephoneNumber",
        "0.9.2342.19200300.100.1.43": "friendlyCountryName",
        "0.9.2342.19200300.100.1.44": "uid",
        "0.9.2342.19200300.100.1.45": "organizationalStatus",
        "0.9.2342.19200300.100.1.46": "janetMailbox",
        "0.9.2342.19200300.100.1.47": "mailPreferenceOption",
        "0.9.2342.19200300.100.1.48": "buildingName",
        "0.9.2342.19200300.100.1.49": "dSAQuality",
        "0.9.2342.19200300.100.1.50": "singleLevelQuality",
        "0.9.2342.19200300.100.1.51": "subtreeMinimumQuality",
        "0.9.2342.19200300.100.1.52": "subtreeMaximumQuality",
        "0.9.2342.19200300.100.1.53": "personalSignature",
        "0.9.2342.19200300.100.1.54": "dITRedirect",
        "0.9.2342.19200300.100.1.55": "audio",
        "0.9.2342.19200300.100.1.56": "documentPublisher",
        "1.2.840.113549.1.9.2": "unstructuredName",
        "1.2.840.113549.1.9.3": "contentType",
        "1.2.840.113549.1.9.4": "messageDigest",
        "1.2.840.113549.1.9.5": "signingTime",
        "1.2.840.113549.1.9.6": "countersignature",
        "1.2.840.113549.1.9.7": "challengePassword",
        "1.2.840.113549.1.9.8": "unstructuredAddress",
        "2.5.4.4": "SN",
        "2.5.4.5": "serialNumber",
        "2.5.4.12": "title",
        "2.5.4.13": "description",
        "2.5.4.14": "searchGuide",
        "2.5.4.15": "businessCategory",
        "2.5.4.16": "postalAddress",
        "2.5.4.17": "postalCode",
        "2.5.4.18": "postOfficeBox",
        "2.5.4.19": "physicalDeliveryOfficeName",
        "2.5.4.20": "telephoneNumber",
        "2.5.4.21": "telexNumber",
        "2.5.4.22": "teletexTerminalIdentifier",
        "2.5.4.23": "facsimileTelephoneNumber",
        "2.5.4.24": "x121Address",
        "2.5.4.25": "internationaliSDNNumber",
        "2.5.4.26": "registeredAddress",
        "2.5.4.27": "destinationIndicator",
        "2.5.4.28": "preferredDeliveryMethod",
        "2.5.4.29": "presentationAddress",
        "2.5.4.30": "supportedApplicationContext",
        "2.5.4.31": "member",
        "2.5.4.32": "owner",
        "2.5.4.33": "roleOccupant",
        "2.5.4.34": "seeAlso",
        "2.5.4.35": "userPassword",
        "2.5.4.36": "userCertificate",
        "2.5.4.37": "cACertificate",
        "2.5.4.38": "authorityRevocationList",
        "2.5.4.39": "certificateRevocationList",
        "2.5.4.40": "crossCertificatePair",
        "2.5.4.41": "name",
        "2.5.4.42": "GN",
        "2.5.4.43": "initials",
        "2.5.4.44": "generationQualifier",
        "2.5.4.45": "x500UniqueIdentifier",
        "2.5.4.46": "dnQualifier",
        "2.5.4.47": "enhancedSearchGuide",
        "2.5.4.48": "protocolInformation",
        "2.5.4.49": "distinguishedName",
        "2.5.4.50": "uniqueMember",
        "2.5.4.51": "houseIdentifier",
        "2.5.4.52": "supportedAlgorithms",
        "2.5.4.53": "deltaRevocationList",
        "2.5.4.54": "dmdName",
        "2.5.4.65": "pseudonym",
        "2.5.4.72": "role",
        "2.5.4.97": "organizationIdentifier",
        "2.5.4.98": "c3",
        "2.5.4.99": "n3",
        "2.5.4.100": "dnsName",
        # Related to Microsoft EV certificates (names from OpenSSL)
        "1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL",
        "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
        "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
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
            if not provided, yields tuples of ``(type, value)``
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
