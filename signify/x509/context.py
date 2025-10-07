from __future__ import annotations

import datetime
import logging
import pathlib
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Any

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

if TYPE_CHECKING:
    from signify.authenticode import CertificateTrustList

logger = logging.getLogger(__name__)


class CertificateStore:
    """A list of :class:`Certificate` objects."""

    def __init__(
        self,
        *args: Certificate | Iterable[Certificate],
        trusted: bool = False,
        ctl: CertificateTrustList | dict[str, list[str] | None] | None = None,
    ):
        """
        :param trusted: If true, all certificates that are appended to this structure
            are set to trusted.
        :param ctl: The certificate trust list to use (if any), or a mapping of SHA-1
            hashes to acceptable EKU's.
        """
        self.trusted = trusted
        self.ctl = ctl
        self.data: list[Certificate] = list(*args)

    def __contains__(self, item: Certificate) -> bool:
        return item in self.data

    def __len__(self) -> int:
        return len(self.data)

    def __iter__(self) -> Iterator[Certificate]:
        yield from self.data

    def __or__(self, other: CertificateStore) -> CertificateStore:
        if self.trusted != other.trusted:
            raise ValueError("Cannot combine trusted and non-trusted stores.")
        if isinstance(other, CombinedCertificateStore):
            return CombinedCertificateStore(self, *other.stores, trusted=self.trusted)
        else:
            return CombinedCertificateStore(self, other, trusted=self.trusted)

    def append(self, elem: Certificate) -> None:
        return self.data.append(elem)

    def extend(self, elem: Iterable[Certificate]) -> None:
        return self.data.extend(elem)

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
            if not isinstance(self.ctl, dict):
                self.ctl.verify_trust(chain, context=context)
            elif context is not None and chain[0].sha1_fingerprint in self.ctl:
                allowed_extended_key_usages = self.ctl[chain[0].sha1_fingerprint]
                if context.extended_key_usages:
                    requested_eku = set(context.extended_key_usages)
                else:
                    requested_eku = set()

                if allowed_extended_key_usages is not None and requested_eku - set(
                    allowed_extended_key_usages
                ):
                    raise CertificateNotTrustedVerificationError(
                        f"The certificate {chain[0]} cannot use extended key usages"
                        f" {requested_eku - set(allowed_extended_key_usages)}."
                    )

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

        :param subject: Certificate subject to look for, as :class:`CertificateName`
        :param int serial_number: Serial number to look for.
        :param issuer: Certificate issuer to look for, as :class:`CertificateName`
        :param str sha256_fingerprint: The SHA-256 fingerprint to look for
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


class CombinedCertificateStore(CertificateStore):
    def __init__(self, *stores: CertificateStore, **kwargs: Any):
        super().__init__(**kwargs)
        self.stores = list(stores)

    def __contains__(self, item: Certificate) -> bool:
        return any(item in store for store in self.stores)

    def __len__(self) -> int:
        return len({c for store in self.stores for c in store})

    def __iter__(self) -> Iterator[Certificate]:
        for store in self.stores:
            yield from store

    def __or__(self, other: CertificateStore) -> CertificateStore:
        if self.trusted != other.trusted:
            raise ValueError("Cannot combine trusted and non-trusted stores.")
        if isinstance(other, CombinedCertificateStore):
            return CombinedCertificateStore(
                *self.stores, *other.stores, trusted=self.trusted
            )
        else:
            return CombinedCertificateStore(*self.stores, other, trusted=self.trusted)

    def append(self, elem: Certificate) -> None:
        raise NotImplementedError()

    def extend(self, elem: Iterable[Certificate]) -> None:
        raise NotImplementedError()

    def verify_trust(
        self, chain: list[Certificate], context: VerificationContext | None = None
    ) -> bool:
        last_error = None
        for store in self.stores:
            try:
                store.verify_trust(chain, context=context)
            except Exception as e:  # noqa: PERF203
                last_error = e
            else:
                return True
        if last_error is not None:
            raise last_error
        return True

    def is_trusted(self, certificate: Certificate) -> bool:
        return any(store.is_trusted(certificate) for store in self.stores)

    def find_certificates(self, **kwargs: Any) -> Iterable[Certificate]:
        seen_certificates = set()
        for store in self.stores:
            for cert in store.find_certificates(**kwargs):
                if cert not in seen_certificates:
                    seen_certificates.add(cert)
                    yield cert


class FileSystemCertificateStore(CertificateStore):
    """A list of :class:`Certificate` objects loaded from the file system."""

    _loaded = False

    def __init__(self, location: pathlib.Path, *args: Any, **kwargs: Any):
        """
        :param location: The file system location for the certificates.
        :param trusted: If true, all certificates that are appended to this structure
            are set to trusted.
        """

        super().__init__(*args, **kwargs)
        self.location = location

    def __iter__(self) -> Iterator[Certificate]:
        self._load()  # TODO: load whenever needed.
        yield from self.data

    def __len__(self) -> int:
        self._load()
        return len(self.data)

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

        :param stores: A list of :class:`CertificateStore` objects  that contain
            certificates
        :param timestamp: The timestamp to verify with. If :const:`None`, the
            current time is used. Must be a timezone-aware timestamp.
        :param key_usages: An iterable with the keyUsages to check for. For valid
            options, see :meth:`certvalidator.CertificateValidator.validate_usage`
        :param extended_key_usages: An iterable with the EKU's to check for. See
            :meth:`certvalidator.CertificateValidator.validate_usage`
        :param optional_eku: If :const:`True`, sets the ``extended_key_usages`` as
            optionally present in the certificates.
        :param allow_legacy: If :const:`True`, allows chain verification if the
            signature hash algorithm is very old (e.g. MD2). Additionally, allows the
            verification of encrypted hashes in :meth:`Certificate.verify_signature`
            instead of encrypted DigestInfo ASN.1 structures. Both are found in the
            wild, but setting to :const:`True` does reduce the reliability of the
            verification.
        :param revocation_mode: Can be either ``soft-fail``, ``hard-fail`` or
            ``require``. See the documentation of
            :meth:`certvalidator.ValidationContext` for the full definition
        :param allow_fetching: If :const:`True`, allows the underlying verification
            module to obtain CRL and OSCP responses when needed.
        :param fetch_timeout: The timeout used when fetching CRL/OSCP responses
        :param crls: List of :class:`asn1crypto.crl.CertificateList` objects to aid in
            verifying revocation statuses.
        :param ocsps: List of :class:`asn1crypto.ocsp.OCSPResponse` objects to aid in
            verifying revocation statuses.
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
        """Iterates over all certificates in the associated stores."""
        for store in self.stores:
            yield from store

    def find_certificate(self, **kwargs: Any) -> Certificate:
        """Finds the certificate as specified by the keyword arguments. See
        :meth:`find_certificates` for all possible arguments. If there is not exactly 1
        certificate matching the parameters, i.e. there are zero or there are
        multiple, an error is raised.

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

        :param certificate: The certificate to build a potential chain for
        :param depth: The maximum depth, used for recursion
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

        :param certificate: The certificate to verify
        :return: A valid certificate chain for this certificate.
        :raises AuthenticodeVerificationError: When the certificate could not be
            verified.
        """

        # we keep track of our asn1 objects to make sure we return Certificate objects
        # when we're done
        to_check_asn1cert = certificate.asn1
        all_certs = {to_check_asn1cert: certificate}

        # we need to get lists of our intermediates and trusted certificates
        intermediates: list[asn1crypto.x509.Certificate] = []
        trust_roots: list[asn1crypto.x509.Certificate] = []
        for store in self.stores:
            for cert in store:
                asn1cert = cert.asn1
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

        :param chain: The certificate chain to verify trust for.
        :return: :const:`True` if the certificate chain is trusted by a certificate
            store.
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
