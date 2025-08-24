Catalog Files and Certificate Trust Lists
=========================================
.. module:: signify.authenticode
   :no-index:

Microsoft has developed a mechanism to provide lists of trusted objects through
so-called *Certificate Trust Lists*. These CTLs are used to distribute the trusted
certificates in
`Microsoft's own Certificate Authority program <https://docs.microsoft.com/en-us/security/trusted-root/release-notes>`_,
but also for catalog files that can contain signatures for any type of file on a
Windows system.

Certificate Trust Lists are not very well documented, but a
`2009 whitepaper <http://download.microsoft.com/download/C/8/8/C8862966-5948-444D-87BD-07B976ADA28C/%5BMS-CAESO%5D.pdf>`_
does a semi-decent job of defining the used structures. Basically, it is a SignedData
object that contains a list of trusted subjects. Both purposes of CTLs use distinct
sets of attributes for their trusted subjects.

Root Program Trust Lists
------------------------
The Microsoft Root Program used to be distributed through Windows Update, although
they are now updated independently. The files used for this are named ``authroot.stl``,
and the subjects are the root certificates being trusted.

Additional attributes in the CTL describe specific conditions for which the root
certificates are valid, allowing selective deprecation of CAs when the need arises.
These are described
`on the Microsoft website <https://docs.microsoft.com/en-us/security/trusted-root/deprecation>`_,
with them being mapped as follows:

Removal
    The root is removed from the CTL, and it is no longer trusted. Since the entry is
    simply removed, we do not need to perform further checks.

EKU Removal
    Specific extended key usages are removed from the root certificate. The EKU is no
    longer available (including for timestamped objects), and is removed from the set
    of allowed EKU's in :attr:`CertificateTrustSubject.extended_key_usages` or added to
    the set of disallowed EKU's in
    :attr:`CertificateTrustSubject.disallowed_extended_key_usages`.

Disallow
   Disallowed certificates are removed from the CTL and added to a separate Disallow
   CTL, preventing them from being installed manually. Since the entry is removed from
   the CTL, we do not need to perform further checks.

Disable
   Disabled certificates are no longer trusted, but digital signatures with a timestamp
   prior to the date of disabling continue to validate. In this case,
   :attr:`CertificateTrustSubject.disallowed_filetime` will be set.

   In the case that only a specific EKU is disabled, it is removed from the set of
   allowed EKU's in :attr:`CertificateTrustSubject.extended_key_usages` or added to the
   set of disallowed EKU's in
   :attr:`CertificateTrustSubject.disallowed_extended_key_usages`.

NotBefore
   When a root certificate is set to NotBefore, a specific EKU capability of a root
   certificate is disabled. Certificates issued after the NotBefore date are no longer
   trusted; certificates issued before the date and digital signatures timestamped
   before this date are still valid. In this case, the
   :attr:`CertificateTrustSubject.not_before_filetime` will be set. In the case that
   this applies to a single EKU,
   :attr:`CertificateTrustSubject.not_before_extended_key_usages` will be set as well.

The :class:`CertificateTrustList` object can be used in combination with a
:class:`signify.x509.CertificateStore` to make sure that the certificates in the store
are valid according to the additional conditions in the CTL. Use
:const:`TRUSTED_CERTIFICATE_STORE` for a certificate store with associated CTL.

Signify uses a separate project (`mscerts <https://pypi.org/project/mscerts/>`_) to
ensure an up-to-date certificate bundle. This project is maintained by the same authors
as Signify.

.. data:: signify.authenticode.TRUSTED_CERTIFICATE_STORE

   A :class:`signify.x509.CertificateStore` with associated
   :class:`CertificateTrustList`.

.. data:: signify.authenticode.TRUSTED_CERTIFICATE_STORE_NO_CTL

   A :class:`signify.x509.CertificateStore` without an associated
   :class:`CertificateTrustList`.

Catalog Files
-------------
A special type of CTL-files Windows catalog files (.cat).

Catalog Files (.cat) are used for externally signing files, mostly used in the case of
driver files. They can be used to sign virtually any type of file. They are usually
found in a subdirectory of ``C:\Windows\System32\CatRoot``.

CertificateTrustList objects
----------------------------
.. autoclass:: signify.authenticode.CertificateTrustList
   :members:
   :special-members: __init__
.. autoclass:: signify.authenticode.CertificateTrustSubject
   :members:
   :special-members: __init__
