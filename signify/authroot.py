import datetime
import hashlib
import pathlib
import struct

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1_modules import rfc2315

from signify import asn1
from signify.asn1 import guarded_ber_decode, ctl
from signify.asn1.helpers import time_to_python
from signify.exceptions import CertificateTrustListParseError, CTLCertificateVerificationError
from signify.signeddata import SignedData
from signify.signerinfo import _get_digest_algorithm

AUTHROOTSTL_URL = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authroot.stl"
AUTHROOTSTL_PATH = pathlib.Path(__file__).resolve().parent / "certs" / "authroot.stl"


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
        return self._subjects.values()

    def verify_trust(self, certificate, *args, **kwargs):
        """Checks whether the specified certificate is valid in the given conditions according to this Certificate Trust
        List.

        :param Certificate certificate: The root certificate to verify
        """

        # Find the subject belonging to this certificate
        subject = self.find_subject(certificate)
        if not subject:
            raise CTLCertificateVerificationError("The root %s is not in the certificate trust list" % certificate)
        return subject.verify_trust(*args, **kwargs)

    def find_subject(self, certificate):
        if self.subject_algorithm == hashlib.sha1:
            identifier = certificate.sha1_fingerprint
        elif self.subject_algorithm == hashlib.sha256:
            identifier = certificate.sha256_fingerprint
        else:
            raise CertificateTrustListParseError("The specified subject algorithm is not yet supported.")

        return self._subjects.get(identifier)

    @classmethod
    def update_stl_file(cls):
        """This downloads the latest version of the authroot.stl file and puts it in place of the locally bundled
        authroot.stl.
        """

        import requests

        with requests.get(AUTHROOTSTL_URL, stream=True) as r, open(str(AUTHROOTSTL_PATH), "wb") as f:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    @classmethod
    def from_stl_file(cls, path=AUTHROOTSTL_PATH):
        with open(path, "rb") as f:
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

        self.key_identifier = bytes(self.attributes.get(asn1.ctl.KeyIdentifier, [None])[0])
        self.subject_name_md5 = bytes(self.attributes.get(asn1.ctl.SubjectNameMd5Hash, [None])[0])
        # TODO: RootProgramCertPolicies not implemented
        self.auth_root_sha256 = bytes(self.attributes.get(asn1.ctl.AuthRootSha256Hash, [None])[0])

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

    def is_valid(self, timestamp):
        # If there is a notBefore time, and there is no NotBeforeEnhkeyUsage, then the validity concerns the entire
        # certificate.
        # If there is both a notBefore time and a NotBeforeEnhkeyUsage, then the notBefore concerns the EKU only
        if self.not_before_filetime is not None and self.not_before_extended_key_usages is None \
                and timestamp < self.not_before_filetime:
            return False
        if self.disallowed_filetime is not None and timestamp > self.disallowed_filetime:
            return False
        return True

    def verify_trust(self, timestamp=None, extended_key_usages=None):
        """Checks whether the specified certificate is valid in the given conditions according to this Certificate Trust
        List.

        :param datetime.datetime timestamp: The timestamp to verify with. If None, the current time is used.
            Must be a timezone-aware timestamp.
        :param Iterable[str] extended_key_usages: An iterable with the EKU's to check for. See
            :meth:`certvalidator.CertificateValidator.validate_usage`
        """

        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc)
        if extended_key_usages is None:
            extended_key_usages = ()

        # Verify the certificate is valid on the specified date
        if not self.is_valid(timestamp):
            raise CTLCertificateVerificationError("The root %s is not trusted on %s (trust range is %s - %s)"
                                                  % (self.friendly_name, timestamp, self.not_before_filetime,
                                                     self.disallowed_filetime))

        # Start by converting the list of provided extended_key_usages to a list of OIDs
        requested_extended_key_usages = set(_lookup_ekus(extended_key_usages))

        # Now check each of the properties
        if self.extended_key_usages and (requested_extended_key_usages - set(self.extended_key_usages)):
            raise CTLCertificateVerificationError(
                "The root %s lists its extended key usages, but %s are not present"
                % (self.friendly_name, requested_extended_key_usages - set(self.extended_key_usages))
            )

        # Disallowed eku's are never allowed
        if self.disallowed_extended_key_usages \
                and any(eku in self.disallowed_extended_key_usages for eku in requested_extended_key_usages):
            raise CTLCertificateVerificationError(
                "The root %s disallows some of the requested EKU's %s"
                % (self.friendly_name, requested_extended_key_usages)
            )

        # We can have a not before filetime
        if self.not_before_filetime is not None and self.not_before_extended_key_usages is not None:
            if timestamp < self.not_before_filetime and \
                    any(eku in self.not_before_extended_key_usages for eku in requested_extended_key_usages):
                raise CTLCertificateVerificationError(
                    "The root %s disallows some of the requested EKU's %s before %s"
                    % (self.friendly_name, requested_extended_key_usages, self.not_before_filetime)
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
