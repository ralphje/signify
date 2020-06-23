from pyasn1.type import univ, namedtype, namedval, tag
from pyasn1_modules import rfc5280, rfc2315


# Based on http://download.microsoft.com/download/C/8/8/C8862966-5948-444D-87BD-07B976ADA28C/%5BMS-CAESO%5D.pdf


class CTLVersion(univ.Integer):
    namedValues = namedval.NamedValues(
        ('v1', 0)
    )


class SubjectUsage(rfc5280.ExtKeyUsageSyntax):
    pass


class ListIdentifier(univ.OctetString):
    pass


class SubjectIdentifier(univ.OctetString):
    pass


class TrustedSubject(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('subjectIdentifier', SubjectIdentifier()),
        namedtype.OptionalNamedType('subjectAttributes', rfc2315.Attributes()),
    )


class TrustedSubjects(univ.SequenceOf):
    componentType = TrustedSubject()


class CertificateTrustList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', CTLVersion('v1')),
        namedtype.NamedType('subjectUsage', SubjectUsage()),
        namedtype.OptionalNamedType('listIdentifier', ListIdentifier()),
        namedtype.OptionalNamedType('sequenceNumber', univ.Integer()),
        namedtype.NamedType('ctlThisUpdate', rfc5280.Time()),
        namedtype.OptionalNamedType('ctlNextUpdate', rfc5280.Time()),
        namedtype.NamedType('subjectAlgorithm', rfc5280.AlgorithmIdentifier()),
        namedtype.OptionalNamedType('trustedSubjects', TrustedSubjects()),
        namedtype.OptionalNamedType('ctlExtensions', rfc5280.Extensions().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
    )


# The following are known attributes


class EnhkeyUsage(rfc5280.ExtKeyUsageSyntax):
    pass


class FriendlyName(univ.OctetString):
    pass


class KeyIdentifier(univ.OctetString):
    pass


class SubjectNameMd5Hash(univ.OctetString):
    pass


class RootProgramCertPolicies(univ.OctetString):  # TODO: not implemented
    pass


class AuthRootSha256Hash(univ.OctetString):
    pass


class DisallowedFiletime(univ.OctetString):
    pass


class RootProgramChainPolicies(rfc5280.ExtKeyUsageSyntax):
    pass


class DisallowedEnhkeyUsage(rfc5280.ExtKeyUsageSyntax):
    pass


class NotBeforeFiletime(univ.OctetString):
    pass


class NotBeforeEnhkeyUsage(rfc5280.ExtKeyUsageSyntax):
    pass
