import datetime
import hashlib
import pathlib
import struct

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1_modules import rfc2315

from signify import asn1
from signify.asn1 import guarded_ber_decode
from signify.asn1.helpers import time_to_python
from signify.exceptions import CertificateTrustListParseError, CTLCertificateVerificationError
from signify.pkcs7.signeddata import SignedData
from signify.pkcs7.signerinfo import _get_digest_algorithm

AUTHROOTSTL_URL = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authroot.stl"
AUTHROOTSTL_PATH = pathlib.Path(__file__).resolve().parent.parent / "certs" / "authroot.stl"
DISALLOWEDSTL_URL = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcert.stl"
DISALLOWEDSTL_PATH = pathlib.Path(__file__).resolve().parent.parent / "certs" / "disallowedcerts.stl"


def _lookup_ekus(extended_key_usages=None):
    """Normally we would be able to use certvalidator for this, but we simply can't now we have done this
    all to ourselves. So we convert the arguments passed to the function to a list of all object-ID tuples.
    """

    if not extended_key_usages:
        return

    # create an inverted map for the fancy names that are supported
    from asn1crypto.x509 import KeyPurposeId
    inverted_map = {v: tuple(map(int, k.split("."))) for k, v in KeyPurposeId._map.items()}

    # now look for all values
    for eku in extended_key_usages:
        if eku in inverted_map:
            yield inverted_map[eku]
        else:
            yield tuple(map(int, eku.split(".")))


class CertificateTrustList(SignedData):
    """A subclass of :class:`signify.pkcs7.SignedData`, containing a list of trusted root certificates.

    .. attribute:: data

       The underlying ASN.1 data object

    .. attribute:: subject_usage
    .. attribute:: list_identifier
    .. attribute:: sequence_number
    .. attribute:: this_update
    .. attribute:: next_update
    .. attribute:: subject_algorithm

    """
    _expected_content_type = asn1.ctl.CertificateTrustList

    def _parse(self):
        super()._parse()

        self.subject_usage = self.content['subjectUsage'][0]
        self.list_identifier = bytes(self.content['listIdentifier']) if self.content['listIdentifier'].isValue else None
        self.sequence_number = self.content['sequenceNumber']
        self.this_update = time_to_python(self.content['ctlThisUpdate'])
        self.next_update = time_to_python(self.content['ctlNextUpdate'])
        self.subject_algorithm = _get_digest_algorithm(self.content['subjectAlgorithm'],
                                                       location="CertificateTrustList.subjectAlgorithm")
        self._subjects = {}
        for subj in (CertificateTrustSubject(subject) for subject in self.content['trustedSubjects']):
            self._subjects[subj.identifier.hex().lower()] = subj
        # TODO: extensions??

    @property
    def subjects(self):
        """A list of :class:`CertificateTrustSubject` s in this list."""

        return self._subjects.values()

    def verify_trust(self, chain, *args, **kwargs):
        """Checks whether the specified certificate is valid in the given conditions according to this Certificate Trust
        List.

        :param List[Certificate] chain: The certificate chain to verify
        """

        # Find the subject belonging to this certificate
        subject = self.find_subject(chain[0])
        if not subject:
            raise CTLCertificateVerificationError("The root %s is not in the certificate trust list" % chain[0])
        return subject.verify_trust(chain, *args, **kwargs)

    def find_subject(self, certificate):
        """Finds the :class:`CertificateTrustSubject` belonging to the provided :class:`signify.x509.Certificate`.

        :param signify.x509.Certificate certificate: The certificate to look for.
        :rtype: CertificateTrustSubject
        """

        if self.subject_algorithm == hashlib.sha1:
            identifier = certificate.sha1_fingerprint
        elif self.subject_algorithm == hashlib.sha256:
            identifier = certificate.sha256_fingerprint
        else:
            raise CertificateTrustListParseError("The specified subject algorithm is not yet supported.")

        return self._subjects.get(identifier)

    @classmethod
    def update_stl_file(cls, url=AUTHROOTSTL_URL, path=AUTHROOTSTL_PATH):
        """This downloads the latest version of the authroot.stl file and puts it in place of the locally bundled
        authroot.stl.
        """

        import requests

        with requests.get(url, stream=True) as r, open(str(path), "wb") as f:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    @classmethod
    def from_stl_file(cls, path=AUTHROOTSTL_PATH):
        """Loads a :class:`CertificateTrustList` from a specified path."""

        with open(str(path), "rb") as f:
            content, rest = ber_decoder.decode(f.read(), asn1Spec=rfc2315.ContentInfo())
        #
        # from pyasn1 import debug
        # debug.setLogger(debug.Debug('all'))

        if asn1.oids.get(content['contentType']) is not rfc2315.SignedData:
            raise CertificateTrustListParseError("ContentInfo does not contain SignedData")

        data = guarded_ber_decode(content['content'], asn1_spec=rfc2315.SignedData())

        signed_data = cls(data)
        signed_data._rest_data = rest
        return signed_data


class CertificateTrustSubject:
    """A subject listed in a :class:`CertificateTrustList`.

    .. attribute:: data

       The underlying ASN.1 data object

    .. attribute:: attributes

       A dictionary mapping of attribute types to values.

    The following values are extracted from the attributes:

    .. attribute:: extended_key_usages
    .. attribute:: friendly_name
    .. attribute:: key_identifier
    .. attribute:: subject_name_md5
    .. attribute:: auth_root_sha256
    .. attribute:: disallowed_filetime
    .. attribute:: root_program_chain_policies
    .. attribute:: disallowed_extended_key_usages
    .. attribute:: not_before_filetime
    .. attribute:: not_before_extended_key_usages

    """

    def __init__(self, data):
        self.data = data
        self._parse()

    def _parse(self):
        self.identifier = bytes(self.data['subjectIdentifier'])
        self.attributes = self._parse_attributes(self.data['subjectAttributes'])

        self.extended_key_usages = None
        if asn1.ctl.EnhkeyUsage in self.attributes:
            self.extended_key_usages = [tuple(x) for x in self.attributes[asn1.ctl.EnhkeyUsage][0]]

        self.friendly_name = None
        if asn1.ctl.FriendlyName in self.attributes:
            self.friendly_name = bytes(self.attributes[asn1.ctl.FriendlyName][0]).decode("utf-16")

        self.key_identifier = bytes(self.attributes.get(asn1.ctl.KeyIdentifier, [b""])[0])
        self.subject_name_md5 = bytes(self.attributes.get(asn1.ctl.SubjectNameMd5Hash, [b""])[0])
        # TODO: RootProgramCertPolicies not implemented
        self.auth_root_sha256 = bytes(self.attributes.get(asn1.ctl.AuthRootSha256Hash, [b""])[0])

        self.disallowed_filetime = None
        if asn1.ctl.DisallowedFiletime in self.attributes:
            self.disallowed_filetime = self._filetime_to_datetime(self.attributes[asn1.ctl.DisallowedFiletime][0])

        self.root_program_chain_policies = None
        if asn1.ctl.RootProgramChainPolicies in self.attributes:
            self.root_program_chain_policies = [tuple(x) for x in self.attributes[asn1.ctl.RootProgramChainPolicies][0]]

        self.disallowed_extended_key_usages = None
        if asn1.ctl.DisallowedEnhkeyUsage in self.attributes:
            self.disallowed_extended_key_usages = [tuple(x) for x in self.attributes[asn1.ctl.DisallowedEnhkeyUsage][0]]

        self.not_before_filetime = None
        if asn1.ctl.NotBeforeFiletime in self.attributes:
            self.not_before_filetime = self._filetime_to_datetime(self.attributes[asn1.ctl.NotBeforeFiletime][0])

        self.not_before_extended_key_usages = None
        if asn1.ctl.NotBeforeEnhkeyUsage in self.attributes:
            self.not_before_extended_key_usages = [tuple(x) for x in self.attributes[asn1.ctl.NotBeforeEnhkeyUsage][0]]

    def verify_trust(self, chain, context):
        """Checks whether the specified certificate is valid in the given conditions according to this Certificate Trust
        List. This is implemented following the definitions found on
        https://docs.microsoft.com/en-us/security/trusted-root/deprecation:

        Removal
            Removal of a root from the CTL. All certificates that chain to the root are no longer trusted.

        In this case, the entry will not exist. This method cannot check for this.

        EKU Removal
            Removal of a specific EKU from a root certificate. All End entity certificates that chain to this root
            can no longer utilize the removed EKU, independent of whether or not the digital signature was timestamped.

        In this case, the EKU is removed from the set of allowed EKU's in :attr:`extended_key_usages`
        OR added to the set of disallowed EKU's in :attr:`disallowed_extended_key_usages`

        Disallow
            This feature involves adding the certificate to the Disallow CTL. This feature effectively revokes the
            certificate. Users cannot manually install the root and continue to have trust.

        The disallowed authroot.stl will be updated in this case. This CTL will only contain the subject name hashes.

        Disable
            All certificates that chain to a disabled root will no longer be trusted with a very important exception;
            digital signatures with a timestamp prior to the disable date will continue to validate successfully.

        Empirical evidence has shown that in this case, :attr:`disallowed_filetime` will be set. In the case that
        only an EKU is disabled, it is removed from the set of allowed EKU's in :attr:`extended_key_usages`
        OR added to the set of disallowed EKU's in :attr:`disallowed_extended_key_usages`

        NotBefore
            Allows granular disabling of a root certificate or specific EKU capability of a root certificate.
            Certificates issued AFTER the NotBefore date will no longer be trusted, however certificates issued
            BEFORE to the NotBefore date will continue to be trusted. Digital signatures with a timestamp set
            before the NotBefore date will continue to successfully validate.

        In this case, the :attr:`not_before_filetime` will be set. In the case that this applies to a single EKU,
        :attr:`not_before_extended_key_usages` will be set as well.

        :param List[Certificate] chain: The certificate chain to verify.
        :param VerificationContext context: The context to verify with. Mainly the timestamp and extended_key_usages
            are used.
        """

        timestamp = context.timestamp
        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc)
        extended_key_usages = context.extended_key_usages
        if extended_key_usages is None:
            extended_key_usages = ()

        # Start by converting the list of provided extended_key_usages to a list of OIDs
        requested_extended_key_usages = set(_lookup_ekus(extended_key_usages))

        # Now check each of the properties
        if self.extended_key_usages and (requested_extended_key_usages - set(self.extended_key_usages)):
            raise CTLCertificateVerificationError(
                "The root %s lists its extended key usages, but %s are not present"
                % (self.friendly_name, requested_extended_key_usages - set(self.extended_key_usages))
            )

        # The notBefore time does concern the validity of the certificate that is being validated. It must have a
        # notBefore of before the timestamp
        if self.not_before_filetime is not None:
            to_verify_timestamp = chain[-1].valid_from

            if to_verify_timestamp >= self.not_before_filetime:
                # If there is a notBefore time, and there is no NotBeforeEnhkeyUsage, then the validity concerns the
                # entire certificate.
                if self.not_before_extended_key_usages is None:
                    raise CTLCertificateVerificationError(
                        "The root %s is disallowed for certificate issued after %s (certificate is %s)"
                        % (self.friendly_name, self.not_before_filetime, to_verify_timestamp)
                    )
                elif any(eku in self.not_before_extended_key_usages for eku in requested_extended_key_usages):
                    raise CTLCertificateVerificationError(
                        "The root %s disallows requested EKU's %s to certificates issued after %s (certificate is %s)"
                        % (self.friendly_name, requested_extended_key_usages,
                           self.not_before_filetime, to_verify_timestamp)
                    )
        elif self.not_before_extended_key_usages is not None \
                and any(eku in self.not_before_extended_key_usages for eku in requested_extended_key_usages):
            raise CTLCertificateVerificationError(
                "The root %s disallows requested EKU's %s" % (self.friendly_name, requested_extended_key_usages)
            )

        # The DisallowedFiletime time does concern the timestamp of the signature being verified.
        if self.disallowed_filetime is not None:
            if timestamp >= self.disallowed_filetime:
                # If there is a DisallowedFiletime, and there is no DisallowedEnhkeyUsage, then the validity
                # concerns the entire certificate.
                if self.disallowed_extended_key_usages is None:
                    raise CTLCertificateVerificationError(
                        "The root %s is disallowed since %s (requested %s)"
                        % (self.friendly_name, self.disallowed_filetime, timestamp)
                    )
                elif any(eku in self.disallowed_extended_key_usages for eku in requested_extended_key_usages):
                    raise CTLCertificateVerificationError(
                        "The root %s is disallowed for EKU's %s since %s (requested %s at %s)"
                        % (self.friendly_name, self.disallowed_extended_key_usages, self.disallowed_filetime,
                           requested_extended_key_usages, timestamp)
                    )
        elif self.disallowed_extended_key_usages is not None \
                and any(eku in self.disallowed_extended_key_usages for eku in requested_extended_key_usages):
            raise CTLCertificateVerificationError(
                "The root %s disallows requested EKU's %s" % (self.friendly_name, requested_extended_key_usages)
            )

        return True

    @classmethod
    def _parse_attributes(cls, data):
        """Given a set of Attributes, parses them and returns them as a dict

        :param data: The attributes to process
        """

        result = {}
        for attr in data:
            typ = asn1.oids.get(attr['type'])
            values = []
            for value in attr['values']:
                if not isinstance(typ, tuple):
                    # This should transparently handle when the data is encapsulated in an OctetString but we are
                    # not expecting an OctetString
                    try:
                        from pyasn1.type import univ
                        if not isinstance(type, univ.OctetString):
                            _, v = ber_decoder.decode(value, recursiveFlag=0)
                        else:
                            v = value
                        value = guarded_ber_decode(v, asn1_spec=typ())
                    except Exception:
                        value = guarded_ber_decode(value, asn1_spec=typ())
                values.append(value)
            result[typ] = values

        return result

    @classmethod
    def _filetime_to_datetime(cls, filetime):
        if not filetime:
            return

        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        value = struct.unpack("<Q", bytes(filetime))[0]
        return epoch + datetime.timedelta(microseconds=value / 10)
