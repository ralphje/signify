Certificate Trust Lists (authroot.stl)
======================================
.. module:: signify.authenticode

Microsoft has its own root CA verification program. More information about this root program can be found
`on Microsoft's website <https://docs.microsoft.com/en-us/security/trusted-root/release-notes>`_.

Trust of certificates is distributed to Windows computers using Certificate Trust Lists. They used to be updated through
Windows Update, though they are now updated independently. Certificate Trust Lists are not very well documented, but a
`2009 whitepaper <http://download.microsoft.com/download/C/8/8/C8862966-5948-444D-87BD-07B976ADA28C/%5BMS-CAESO%5D.pdf>`_
does a decent job of defining the used structures.

For interpreting the various attributes, we had to do some more extended research. The following lists the
`deprecation policies in place <https://docs.microsoft.com/en-us/security/trusted-root/deprecation>`_
and how we have found that they are mapped to attributes in the CTL.

.. admonition:: CTL deprecation policies

   Removal
           *Removal of a root from the CTL. All certificates that chain to the root are no longer trusted.*

       In this case, the entry will be removed from the CTL; we do not need to perform further checks.

   EKU Removal
           *Removal of a specific EKU from a root certificate. All End entity certificates that chain to this root
           can no longer utilize the removed EKU, independent of whether or not the digital signature was
           timestamped.*

       The EKU is removed from the set of allowed EKU's in :attr:`CertificateTrustSubject.extended_key_usages`
       or added to the set of disallowed EKU's in :attr:`CertificateTrustSubject.disallowed_extended_key_usages`.

   Disallow
           *This feature involves adding the certificate to the Disallow CTL. This feature effectively revokes the
           certificate. Users cannot manually install the root and continue to have trust.*

       Disallowed certificates are put in a separate authroot.stl file, and removed from the normal CTL. We do not
       verify disallowed certificates.

   Disable
           *All certificates that chain to a disabled root will no longer be trusted with a very important
           exception; digital signatures with a timestamp prior to the disable date will continue to validate
           successfully.*

       Empirical evidence has shown that in this case, :attr:`CertificateTrustSubject.disallowed_filetime` will be set.
       In the case that only an EKU is disabled, it is removed from the set of allowed EKU's in
       :attr:`CertificateTrustSubject.extended_key_usages`  or added to the set of disallowed EKU's in
       :attr:`CertificateTrustSubject.disallowed_extended_key_usages`

   NotBefore
           *Allows granular disabling of a root certificate or specific EKU capability of a root certificate.
           Certificates issued AFTER the NotBefore date will no longer be trusted, however certificates issued
           BEFORE to the NotBefore date will continue to be trusted. Digital signatures with a timestamp set
           before the NotBefore date will continue to successfully validate.*

       In this case, the :attr:`CertificateTrustSubject.not_before_filetime` will be set. In the case that this applies
       to a single EKU, :attr:`CertificateTrustSubject.not_before_extended_key_usages` will be set as well.


The :class:`CertificateTrustList` object can be used in combination with a :class:`signify.x509.CertificateStore` to
make sure that the certificates in the store are valid according to the additional conditions in the CTL.
Use :const:`TRUSTED_CERTIFICATE_STORE` for a certificate store with associated CTL.

.. autoclass:: CertificateTrustList
   :members:
.. autoclass:: CertificateTrustSubject
   :members:

.. data:: TRUSTED_CERTIFICATE_STORE

   A :class:`signify.x509.CertificateStore` with associated :class:`CertificateTrustList`.


.. data:: TRUSTED_CERTIFICATE_STORE_NO_CTL

   A :class:`signify.x509.CertificateStore` without an associated :class:`CertificateTrustList`.
