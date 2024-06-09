from __future__ import annotations

import datetime
import logging
import pathlib
from typing import Any, Iterable, Iterator, List

import asn1crypto.crl
import asn1crypto.ocsp
import asn1crypto.x509
from certvalidator import CertificateValidator, ValidationContext
from typing_extensions import Literal

from signify.exceptions import (
    CertificateNotTrustedVerificationError,
    CertificateVerificationError,
    VerificationError,
)
from signify.x509 import Certificate, CertificateName

logger = logging.getLogger(__name__)


class CertificateStore(List[Certificate]):
    """A list of :class:`Certificate` objects."""

    def __init__(
        self,
        *args: Certificate | Iterable[Certificate],
        trusted: bool = False,
        ctl: Any | None = None,
        **kwargs: Any,
    ):
        """
        :param bool trusted: If true, all certificates that are appended to this
            structure are set to trusted.
        :param CertificateTrustList ctl: The certificate trust list to use (if any)
        """
        super().__init__(*args, **kwargs)
        self.trusted = trusted
        self.ctl = ctl

    def append(self, elem: Certificate) -> None:
        return super().append(elem)

    def verify_trust(
        self, chain: list[Certificate], context: VerificationContext | None = None
    ) -> bool:
        """Verifies that the chain is trusted given the context."""

        if not self.is_trusted(chain[0]):
            # use subclass of CertificateVerificationError to allow
            # VerificationContext.verify_trust to throw a better
            # exception
            raise CertificateNotTrustedVerificationError(
                f"The certificate {chain[0]} is not trusted by the store."
            )

        if self.ctl is not None:
            self.ctl.verify_trust(chain, context=context)

        return True

    def is_trusted(self, certificate: Certificate) -> bool:
        """Returns whether the provided certificate is trusted by this certificate
         store.

        .. warning::

           This check does not verify that the certificate is valid according to the
           Trust List, if set. It merely checks that the provided certificate is in a
           trusted certificate store. You still need to verify the chain for its full
           trust.
        """

        return self.trusted and certificate in self

    def find_certificate(self, **kwargs: Any) -> Certificate:
        """Finds the certificate as specified by the keyword arguments. See
        :meth:`find_certificates` for all possible arguments. If there is not exactly
        1 certificate matching the parameters, i.e. there are zero or there are
        multiple, an error is raised.

        :rtype: Certificate
        :raises KeyError:
        """

        certificates = list(self.find_certificates(**kwargs))

        if len(certificates) == 0:
            raise KeyError("the specified certificate does not exist")
        elif len(certificates) > 1:
            raise KeyError("there are multiple certificates matching the query")

        return certificates[0]

    def find_certificates(
        self,
        *,
        subject: CertificateName | None = None,
        serial_number: int | None = None,
        issuer: CertificateName | None = None,
        sha256_fingerprint: str | None = None,
    ) -> Iterable[Certificate]:
        """Finds all certificates given by the specified properties. A property can be
        omitted by specifying :const:`None`. Calling this function without arguments is
        the same as iterating over this store

        :param CertificateName subject: Certificate subject to look for, as
            CertificateName
        :param int serial_number: Serial number to look for.
        :param CertificateName issuer: Certificate issuer to look for, as
            CertificateName
        :param str sha256_fingerprint: The SHA-256 fingerprint to look for
        :rtype: Iterable[Certificate]
        """

        for certificate in self:
            if subject is not None and certificate.subject != subject:
                continue
            if serial_number is not None and certificate.serial_number != serial_number:
                continue
            if issuer is not None and certificate.issuer != issuer:
                continue
            if sha256_fingerprint is not None and (
                certificate.sha256_fingerprint.replace(" ", "").lower()
                != sha256_fingerprint.replace(" ", "").lower()
            ):
                continue
            yield certificate


class FileSystemCertificateStore(CertificateStore):
    """A list of :class:`Certificate` objects loaded from the file system."""

    _loaded = False

    def __init__(self, location: pathlib.Path, *args: Any, **kwargs: Any):
        """
        :param pathlib.Path location: The file system location for the certificates.
        :param bool trusted: If true, all certificates that are appended to this
            structure are set to trusted.
        """

        super().__init__(*args, **kwargs)
        self.location = location

    def __iter__(self) -> Iterator[Certificate]:
        self._load()  # TODO: load whenever needed.
        return super().__iter__()

    def __len__(self) -> int:
        self._load()
        return super().__len__()

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True

        if self.location.is_dir():
            for file in self.location.glob("*"):
                with file.open("rb") as f:
                    self.extend(Certificate.from_pems(f.read()))
        else:
            with self.location.open("rb") as f:
                self.extend(Certificate.from_pems(f.read()))


class VerificationContext:
    def __init__(
        self,
        *stores: CertificateStore,
        timestamp: datetime.datetime | None = None,
        key_usages: Iterable[str] | None = None,
        extended_key_usages: Iterable[str] | None = None,
        optional_eku: bool = True,
        allow_legacy: bool = True,
        revocation_mode: Literal["soft-fail", "hard-fail", "require"] = "soft-fail",
        allow_fetching: bool = False,
        fetch_timeout: int = 30,
        crls: Iterable[asn1crypto.crl.CertificateList] | None = None,
        ocsps: Iterable[asn1crypto.ocsp.OCSPResponse] | None = None,
    ):
        """A context holding properties about the verification of a signature or
        certificate.

        :param Iterable[CertificateStore] stores: A list of CertificateStore objects
        that contain certificates
        :param datetime.datetime timestamp: The timestamp to verify with. If None, the
            current time is used. Must be a timezone-aware timestamp.
        :param Iterable[str] key_usages: An iterable with the keyUsages to check for.
            For valid options, see
            :meth:`certvalidator.CertificateValidator.validate_usage`
        :param Iterable[str] extended_key_usages: An iterable with the EKU's to check
            for. See :meth:`certvalidator.CertificateValidator.validate_usage`
        :param bool optional_eku: If True, sets the extended_key_usages as optionally
            present in the certificates.
        :param bool allow_legacy: If True, allows chain verification if the signature
            hash algorithm is very old (e.g. MD2). Additionally, allows the
            SignedInfo encryptedDigest to contain an encrypted hash instead of an
            encrypted DigestInfo ASN.1 structure. Both are found in the wild,
            but setting to True does reduce the reliability of the verification.
        :param str revocation_mode: Can be either soft-fail, hard-fail or require. See
            the documentation of :meth:`certvalidator.ValidationContext` for the full
            definition
        :param bool allow_fetching: If True, allows the underlying verification module
            to obtain CRL and OSCP responses when needed.
        :param int fetch_timeout: The timeout used when fetching CRL/OSCP responses
        :param Iterable[asn1crypto.crl.CertificateList] crls: List of
            :class:`asn1crypto.crl.CertificateList` objects to  aid in verifying
            revocation statuses.
        :param Iterable[asn1crypto.ocsp.OCSPResponse] ocsps: List of
            :class:`asn1crypto.ocsp.OCSPResponse` objects to aid in verifying
            revocation statuses.
        """

        self.stores = list(stores)
        self.timestamp = timestamp
        self.key_usages = key_usages
        self.extended_key_usages = extended_key_usages
        self.optional_eku = optional_eku
        self.allow_legacy = allow_legacy
        self.revocation_mode = revocation_mode
        self.allow_fetching = allow_fetching
        self.fetch_timeout = fetch_timeout
        self.crls = crls
        self.ocsps = ocsps

    def add_store(self, store: CertificateStore) -> None:
        """Adds a certificate store to the VerificationContext"""
        self.stores.append(store)

    @property
    def certificates(self) -> Iterator[Certificate]:
        """Iterates over all certificates in the associated stores.

        :rtype: Iterable[Certificate]
        """
        for store in self.stores:
            yield from store

    def find_certificate(self, **kwargs: Any) -> Certificate:
        """Finds the certificate as specified by the keyword arguments. See
        :meth:`find_certificates` for all possible arguments. If there is not exactly 1
        certificate matching the parameters, i.e. there are zero or there are
        multiple, an error is raised.

        :rtype: Certificate
        :raises KeyError:
        """

        certificates = list(self.find_certificates(**kwargs))

        if len(certificates) == 0:
            raise KeyError("the specified certificate does not exist")
        elif len(certificates) > 1:
            raise KeyError("there are multiple certificates matching the query")

        return certificates[0]

    def find_certificates(self, **kwargs: Any) -> Iterator[Certificate]:
        """Finds all certificates given by the specified keyword arguments. See
        :meth:`CertificateStore.find_certificates` for a list of all supported
        arguments.

        :rtype: Iterable[Certificate]
        """

        seen_certs = []

        for store in self.stores:
            for certificate in store.find_certificates(**kwargs):
                if certificate in seen_certs:
                    continue
                seen_certs.append(certificate)
                yield certificate

    def potential_chains(
        self, certificate: Certificate, depth: int = 10
    ) -> Iterator[list[Certificate]]:
        """Returns all possible chains from the provided certificate, solely based on
        issuer/subject matching.

        **THIS METHOD DOES NOT VERIFY WHETHER A CHAIN IS ACTUALLY VALID**.
        Use :meth:`verify` for that.

        :param Certificate certificate: The certificate to build a potential chain for
        :param int depth: The maximum depth, used for recursion
        :rtype: Iterable[Iterable[Certificate]]
        :return: A iterable of all possible certificate chains
        """

        # TODO:
        # Info from the authority key identifier extension can be used to
        # eliminate possible options when multiple keys with the same
        # subject exist, such as during a transition, or with cross-signing.

        if self.is_trusted(certificate):
            yield [certificate]
            return
        elif depth <= 0:
            return

        for candidate in self.find_certificates(subject=certificate.issuer):
            for chain in self.potential_chains(candidate, depth=depth - 1):
                # prevent recursion on itself
                if certificate in chain:
                    continue
                else:
                    yield [*chain, certificate]

    def verify(self, certificate: Certificate) -> list[Certificate]:
        """Verifies the certificate, and its chain.

        :param Certificate certificate: The certificate to verify
        :return: A valid certificate chain for this certificate.
        :rtype: Iterable[Certificate]
        :raises AuthenticodeVerificationError: When the certificate could not be
            verified.
        """

        # we keep track of our asn1 objects to make sure we return Certificate objects
        # when we're done
        to_check_asn1cert = certificate.data
        all_certs = {to_check_asn1cert: certificate}

        # we need to get lists of our intermediates and trusted certificates
        intermediates: list[asn1crypto.x509.Certificate] = []
        trust_roots: list[asn1crypto.x509.Certificate] = []
        for store in self.stores:
            for cert in store:
                asn1cert = cert.data
                # we short-circuit the check here to ensure we do not check too much
                # possibilities
                (trust_roots if store.trusted else intermediates).append(asn1cert)
                all_certs[asn1cert] = cert

        # construct the context and validator for certvalidator
        timestamp = self.timestamp
        context = ValidationContext(
            trust_roots=list(trust_roots),
            moment=timestamp,
            weak_hash_algos=set() if self.allow_legacy else None,
            revocation_mode=self.revocation_mode,
            allow_fetching=self.allow_fetching,
            crl_fetch_params={"timeout": self.fetch_timeout},
            ocsp_fetch_params={"timeout": self.fetch_timeout},
            crls=self.crls,
            ocsps=self.ocsps,
        )
        validator = CertificateValidator(
            end_entity_cert=to_check_asn1cert,
            intermediate_certs=list(intermediates),
            validation_context=context,
        )

        # verify the chain
        try:
            chain = validator.validate_usage(
                key_usage=set(self.key_usages) if self.key_usages else set(),
                extended_key_usage=(
                    set(self.extended_key_usages) if self.extended_key_usages else set()
                ),
                extended_optional=self.optional_eku,
            )
        except Exception as e:
            raise CertificateVerificationError(
                f"Chain verification from {certificate} failed: {e}"
            )

        signify_chain = [all_certs[x] for x in chain]
        self.verify_trust(signify_chain)
        return signify_chain

    def is_trusted(self, certificate: Certificate) -> bool:
        """Returns whether the provided certificate is trusted by a trusted certificate
        store.

        .. warning::

           This check does not verify that the certificate is valid according to the
           Trust List, if set. It merely checks that the provided certificate is in a
           trusted certificate store. You still need to verify the chain for its full
           trust.
        """

        for store in self.stores:
            if store.is_trusted(certificate):
                return True
        return False

    def verify_trust(self, chain: list[Certificate]) -> bool:
        """Determines whether the given certificate chain is trusted by a trusted
        certificate store.

        :param List[Certificate] chain: The certificate chain to verify trust for.
        :return: True if the certificate chain is trusted by a certificate store.
        """

        exc = None

        for store in self.stores:
            try:
                if store.verify_trust(chain, context=self):
                    return True
            except CertificateNotTrustedVerificationError:  # noqa: PERF203
                pass  # ignore this error, and catch it at function end
            except VerificationError as e:
                exc = e

        if exc:
            raise exc

        raise CertificateVerificationError(
            f"The trust for {chain} could not be verified, "
            "as it is not trusted by any store"
        )
