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
        :param str location: The file system location for the certificates.
        :param bool trusted: If true, all certificates that are appended to this structure are set to trusted.
        """

        super().__init__(*args, **kwargs)
        self.location = location

    def __iter__(self):
        self._load()  # TODO: load whenever needed.
        return super().__iter__()

    def _load(self):
        if self._loaded:
            return
        self._loaded = True

        for file in self.location.glob("*"):
            with open(str(file), "rb") as f:
                self.append(Certificate.from_pem(f.read()))


class VerificationContext(object):
    def __init__(self, *stores, timestamp=None, key_usages=None, extended_key_usages=None, optional_eku=True,
                 allow_legacy=True):
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
        """

        self.stores = stores

        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc)
        self.timestamp = timestamp
        self.key_usages = key_usages
        self.extended_key_usages = extended_key_usages
        self.optional_eku = optional_eku
        self.allow_legacy = allow_legacy

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

        :param signify.asn1.x509.Name subject: Certificate subject to look for.
        :param int serial_number: Serial number to look for.
        :param signify.asn1.x509.Name issuer: Certificate issuer to look for.
        :rtype: Iterable[Certificate]
        """

        for certificate in self.certificates:
            if subject is not None and certificate.subject != subject:
                continue
            if serial_number is not None and certificate.serial_number != serial_number:
                continue
            if issuer is not None and certificate.issuer != issuer:
                continue
            yield certificate

    def verify(self, certificate):
        """Verifies the certificate, and its chain.

        :param Certificate certificate: The certificate to verify
        :return: A list of valid certificate chains for this certificate.
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
                asn1cert = certificate.to_asn1crypto
                (trust_roots if store.trusted else intermediates).append(asn1cert)
                all_certs[asn1cert] = cert

        # construct the context and validator for certvalidator
        context = ValidationContext(trust_roots=list(trust_roots),
                                    moment=self.timestamp,
                                    weak_hash_algos=set() if self.allow_legacy else None)
        validator = CertificateValidator(end_entity_cert=to_check_asn1cert,
                                         intermediate_certs=list(intermediates),
                                         validation_context=context)

        # verify the chain
        try:
            chain = validator.validate_usage(key_usage=set(self.key_usages) if self.key_usages else set(),
                                             extended_key_usage=set(self.extended_key_usages)
                                                                if self.extended_key_usages else set(),
                                             extended_optional=self.optional_eku)
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
            if certificate in store and store.trusted:
                return True
        return False
