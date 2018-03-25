import datetime
import logging

from signify.certificates import Certificate

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
    def __init__(self, *stores, timestamp=None, extended_key_usage=None, allow_legacy=True):
        """A context holding properties about the verification of a signature or certificate.

        :param Iterable[CertificateStore] stores: A list of CertificateStore objects that contain certificates
        :param datetime.datetime timestamp: The timestamp to verify with. If None, the current time is used.
            Must be a timezone-aware timestamp.
        :param tuple extended_key_usage: A tuple with the OID of an EKU to check for. Typical values are
            asn1.oids.EKU_CODE_SIGNING and asn1.oids.EKU_TIME_STAMPING
        :param bool allow_legacy: If True, allows chain verification using pyOpenSSL if the signature hash algorithm
            is too old to be supported by cryptography (e.g. MD2). Additionally, allows the SignedInfo encryptedDigest
            to contain an encrypted hash instead of an encrypted DigestInfo ASN.1 structure. Both are found in the wild,
            but setting to True does reduce the reliability of the verification.
        """

        self.stores = stores

        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc)
        self.timestamp = timestamp
        self.extended_key_usage = extended_key_usage
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

    def is_trusted(self, certificate):
        """Determines whether the given certificate is in a trusted certificate store.

        :param Certificate certificate: The certificate to verify trust for.
        :return: True if the certificate is in a trusted certificate store.
        """

        for store in self.stores:
            if certificate in store and store.trusted:
                return True
        return False
