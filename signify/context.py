import datetime
import logging

from certvalidator import ValidationContext, CertificateValidator

from signify.certificates import Certificate
from signify.exceptions import VerificationError

logger = logging.getLogger(__name__)


class CertificateStore(list):
    """A list of :class:`Certificate` objects."""

    def __init__(self, *args, trusted=False, **kwargs):
        """
        :param bool trusted: If true, all certificates that are appended to this structure are set to trusted.
        """
        super().__init__(*args, **kwargs)
        self.trusted = trusted

    def append(self, elem):
        return super().append(elem)


class FileSystemCertificateStore(CertificateStore):
    """A list of :class:`Certificate` objects loaded from the file system."""

    _loaded = False

    def __init__(self, location, *args, **kwargs):
        """
        :param pathlib.Path location: The file system location for the certificates.
        :param bool trusted: If true, all certificates that are appended to this structure are set to trusted.
        """

        super().__init__(*args, **kwargs)
        self.location = location

    def __iter__(self):
        self._load()  # TODO: load whenever needed.
        return super().__iter__()

    def __len__(self):
        self._load()
        return super().__len__()

    def _load(self):
        if self._loaded:
            return
        self._loaded = True

        if self.location.is_dir():
            for file in self.location.glob("*"):
                with open(str(file), "rb") as f:
                    self.extend(Certificate.from_pems(f.read()))
        else:
            with open(str(self.location), "rb") as f:
                self.extend(Certificate.from_pems(f.read()))


class VerificationContext(object):
    def __init__(self, *stores, timestamp=None, key_usages=None, extended_key_usages=None, optional_eku=True,
                 allow_legacy=True, revocation_mode='soft-fail', allow_fetching=False, fetch_timeout=30,
                 crls=None, ocsps=None):
        """A context holding properties about the verification of a signature or certificate.

        :param Iterable[CertificateStore] stores: A list of CertificateStore objects that contain certificates
        :param datetime.datetime timestamp: The timestamp to verify with. If None, the current time is used.
            Must be a timezone-aware timestamp.
        :param Iterable[str] key_usages: An iterable with the keyUsages to check for. For valid options, see
            :meth:`certvalidator.CertificateValidator.validate_usage`
        :param Iterable[str] extended_key_usages: An iterable with the EKU's to check for. See
            :meth:`certvalidator.CertificateValidator.validate_usage`
        :param bool optional_eku: If True, sets the extended_key_usages as optionally present in the certificates.
        :param bool allow_legacy: If True, allows chain verification if the signature hash algorithm
            is very old (e.g. MD2). Additionally, allows the SignedInfo encryptedDigest
            to contain an encrypted hash instead of an encrypted DigestInfo ASN.1 structure. Both are found in the wild,
            but setting to True does reduce the reliability of the verification.
        :param str revocation_mode: Can be either soft-fail, hard-fail or require. See the documentation of
            :meth:`certvalidator.ValidationContext` for the full definition
        :param bool allow_fetching: If True, allows the underlying verification module to obtain CRL and OSCP responses
            when needed.
        :param int fetch_timeout: The timeout used when fetching CRL/OSCP responses
        :param Iterable[asn1crypto.crl.CertificateList] crls: List of :class:`asn1crypto.crl.CertificateList` objects to
            aid in verifying revocation statuses.
        :param Iterable[asn1crypto.ocsp.OCSPResponse] ocsps: List of :class:`asn1crypto.ocsp.OCSPResponse` objects to
            aid in verifying revocation statuses.
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

    def add_store(self, store):
        """Adds a certificate store to the VerificationContext"""
        self.stores.append(store)

    @property
    def certificates(self):
        """Iterates over all certificates in the associated stores.

        :rtype: Iterable[Certificate]
        """
        for store in self.stores:
            yield from store

    def find_certificates(self, *, subject=None, serial_number=None, issuer=None):
        """Finds all certificates given by the specified properties. A property can be omitted by specifying
        :const:`None`. Calling this function without arguments is the same as using :meth:`certificates`

        :param CertificateName subject: Certificate subject to look for, as CertificateName
        :param int serial_number: Serial number to look for.
        :param CertificateName issuer: Certificate issuer to look for, as CertificateName
        :rtype: Iterable[Certificate]
        """

        seen_certs = []
        for certificate in self.certificates:
            if subject is not None and certificate.subject != subject:
                continue
            if serial_number is not None and certificate.serial_number != serial_number:
                continue
            if issuer is not None and certificate.issuer != issuer:
                continue
            if certificate in seen_certs:
                continue
            seen_certs.append(certificate)
            yield certificate

    def potential_chains(self, certificate, depth=10):
        """Returns all possible chains from the provided certificate, solely based on issuer/subject matching.

        **THIS METHOD DOES NOT VERIFY WHETHER A CHAIN IS ACTUALLY VALID**. Use :meth:`verify` for that.

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
            for chain in self.potential_chains(candidate, depth=depth-1):
                # prevent recursion on itself
                if certificate in chain:
                    continue
                else:
                    yield chain + [certificate]

    def verify(self, certificate):
        """Verifies the certificate, and its chain.

        :param Certificate certificate: The certificate to verify
        :return: A valid certificate chain for this certificate.
        :rtype: Iterable[Certificate]
        :raises AuthenticodeVerificationError: When the certificate could not be verified.
        """

        # we keep track of our asn1 objects to make sure we return Certificate objects when we're done
        to_check_asn1cert = certificate.to_asn1crypto
        all_certs = {to_check_asn1cert: certificate}

        # we need to get lists of our intermediates and trusted certificates
        intermediates, trust_roots = [], []
        for store in self.stores:
            for cert in store:
                asn1cert = cert.to_asn1crypto
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
            crl_fetch_params={'timeout': self.fetch_timeout},
            ocsp_fetch_params={'timeout': self.fetch_timeout},
            crls=self.crls,
            ocsps=self.ocsps
        )
        validator = CertificateValidator(
            end_entity_cert=to_check_asn1cert,
            intermediate_certs=list(intermediates),
            validation_context=context
        )

        # verify the chain
        try:
            chain = validator.validate_usage(
                key_usage=set(self.key_usages) if self.key_usages else set(),
                extended_key_usage=set(self.extended_key_usages) if self.extended_key_usages else set(),
                extended_optional=self.optional_eku
            )
        except Exception as e:
            raise VerificationError("Chain verification from %s failed: %s" % (certificate, e))
        else:
            return [all_certs[x] for x in chain]

    def is_trusted(self, certificate):
        """Determines whether the given certificate is in a trusted certificate store.

        :param Certificate certificate: The certificate to verify trust for.
        :return: True if the certificate is in a trusted certificate store.
        """

        for store in self.stores:
            if store.trusted and certificate in store:
                return True
        return False
