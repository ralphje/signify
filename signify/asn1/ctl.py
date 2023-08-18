from pyasn1.type import univ, namedtype, namedval, tag
from pyasn1_modules import rfc5280, rfc2315


# Based on http://download.microsoft.com/download/C/8/8/C8862966-5948-444D-87BD-07B976ADA28C/%5BMS-CAESO%5D.pdf


class CTLVersion(univ.Integer):  # type: ignore[misc]
    namedValues = namedval.NamedValues(
        ('v1', 0)
    )


class SubjectUsage(rfc5280.ExtKeyUsageSyntax):  # type: ignore[misc]
    pass


class ListIdentifier(univ.OctetString):  # type: ignore[misc]
    pass


class SubjectIdentifier(univ.OctetString):  # type: ignore[misc]
    pass


class TrustedSubject(univ.Sequence):  # type: ignore[misc]
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('subjectIdentifier', SubjectIdentifier()),
        namedtype.OptionalNamedType('subjectAttributes', rfc2315.Attributes()),
    )


class TrustedSubjects(univ.SequenceOf):  # type: ignore[misc]
    componentType = TrustedSubject()


class CertificateTrustList(univ.Sequence):  # type: ignore[misc]
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


class EnhkeyUsage(rfc5280.ExtKeyUsageSyntax):  # type: ignore[misc]
    pass


class FriendlyName(univ.OctetString):  # type: ignore[misc]
    pass


class KeyIdentifier(univ.OctetString):  # type: ignore[misc]
    pass


class SubjectNameMd5Hash(univ.OctetString):  # type: ignore[misc]
    pass


class RootProgramCertPolicies(univ.OctetString):  # type: ignore[misc]  # TODO: not implemented
    pass


class AuthRootSha256Hash(univ.OctetString):  # type: ignore[misc]
    pass


class DisallowedFiletime(univ.OctetString):  # type: ignore[misc]
    pass


class RootProgramChainPolicies(rfc5280.ExtKeyUsageSyntax):  # type: ignore[misc]
    pass


class DisallowedEnhkeyUsage(rfc5280.ExtKeyUsageSyntax):  # type: ignore[misc]
    pass


class NotBeforeFiletime(univ.OctetString):  # type: ignore[misc]
    pass


class NotBeforeEnhkeyUsage(rfc5280.ExtKeyUsageSyntax):  # type: ignore[misc]
    pass
