Release notes
=============
This page contains the most significant changes in Signify between each release.

v0.8.0 (unreleased)
-------------------
* Add support for page hashes contained within the ``SpcPeImageData`` structure.
* Add support for MSI files through ``SignedMsi`` class, contributed by @HugoC. The
  ``AuthenticodeFile.detect`` class method auto-detects the file type, and the class
  provides a transparent interface. You must install support for MSI files by using
  ``pip install signify[msi]``
* The transparent ``AuthenticodeFile`` interface also has the subclass
  ``AuthenticodeSignedDataFile`` that allows using a ``AuthenticodeSignedData`` object
  as its base object, enabling easy parsing of PKCX files. Note that the
  ``get_fingerprint`` method is not implemented, requiring all fingerprints to be
  provided during verification.

* Drop support for Python 3.8, as it reached end-of-life in October 2024. The minimum
  required version is now 3.9.
* Renamed ``SpcInfo`` to ``IndirectData``, and split off ``PeImageData`` into a
  separate class.
* Add support for the ``microsoft_spc_siginfo`` OID in the ``SpcIndirectDataContent``
  structure, used in signing MSI files.
* Add support for ``SpcRelaxedPeMarkerCheck`` and ``PlatformManifestBinaryID`` as
  SignerInfo attributes, although their exact purpose is currently unknown.
* Refactor classes to store the ASN.1 object in the property ``asn1``, and use
  property methods as data accessors, instead of assigning all attributes during class
  initialization.
* ``CertificateStore`` is no longer a subclass of ``list``, as that was type unsafe,
  and could result in loosing its attributes.
* ``AuthenticodeFingerprinter`` is now a ``SignedPEFingerprinter``, as it is scoped for
  that use case (and not for MSI files).
* Added ``AuthenticodeSignedData.iter_recursive_nested`` to allow easier access to
  nested ``SignedData`` objects.

* Resolve bug with parsing of ``microsoft_spc_financial_criteria``.

v0.7.1 (2024-09-11)
-------------------
* Fix minor bug in parsing of ``CertificateTrustSubject.root_program_chain_policies``.

v0.7.0 (2024-09-11)
-------------------
* Remove dependency of ``pyasn1`` and ``pyasn1-modules`` entirely to provide more robust
  parsing of ASN.1 structures, adding the ability to parse structures independent of
  RFC version. Certain bugs we've encountered in the past, have now been resolved
  as a result of this. On top of that, structures defined in the replacement,
  ``asn1crypto``, are a lot more Pythonic, and parsing speed has been sliced in more
  than half.

  This does have a serious impact if you use certain functions to deeply inspect the
  original data (as all these structures have now changed) and on some parts of the API
  to better align with the new dependency. Most notably, all OIDs are now strings,
  rather than integer tuples, and references to attributes or specific types are now
  strings as well (such as in attribute lists). These strings can be in dotted form,
  but most commonly are a representation as provided by ``asn1crypto`` or ourselves.

* Add (default) option to swallow ``SignedPEParseError`` while parsing a PE file's
  certificate table. This allows checking certificates until such a parse error occurs,
  better aligning with how Windows handles these cases.

  ``SignedPEFile.signed_datas`` will no longer raise an exception when anything goes
  wrong, and will simply stop without yielding anything if no valid
  ``AuthenticodeSignedData`` is found.

  ``SignedPEFile.verify`` will raise a ``AuthenticodeNotSignedError`` when there's no
  valid ``AuthenticodeSignedData``, instead of a ``SignedPEParseError``.

  The former behaviour can be restored with the ``ignore_parse_errors`` argument to
  ``SignedPEFile.verify`` and ``SignedPEFile.iter_signed_datas``. The latter method
  has been changed to keyword-arguments only.

* Add support for ``AuthenticodeSignedData`` versions other than v1
* Add support for ``SignerInfo`` versions other than v1
* Fix bug that could cause out-of-bound reads during parsing of the PE file's
  certificate table
* Correctly handle the lifetime-signing EKU (OID 1.3.6.1.4.1.311.10.3.13) by ignoring
  the countersignature's timestamp during verification of the certification chain when
  this is set on the end-entity's certificate. Note that the private
  ``SignerInfo._verify_issuer`` has slightly changed semantics based on this.
* Return the certificate chain(s) in ``AuthenticodeSignedData.verify`` and
  the used ``AuthenticodeSignedData`` and chains in ``SignedPEFile.verify``

* Parse the ``SpcPeImageData`` as part of the SpcInfo. This adds the attributes
  ``image_flags`` and ``image_publisher``, although this information is never used.
* Parse the ``SpcStatementType`` as part of the authenticated attributes of the
  ``AuthenticodeSignerInfo``. This adds the attribute ``statement_types``, although this
  information is never used.
* Parse the ``SpcFinancialCriteria`` (``microsoft_spc_financial_criteria``) and
  (partially) ``SpcSpAgencyInfo`` (``microsoft_spc_sp_agency_info``) as part of the
  ``extensions`` of ``Certificate``. These extensions are poorly documented, but may
  provide some additional information, such as when researching CVE-2019–1388.

v0.6.1 (2024-03-21)
-------------------
* Require at least version v4.6.0 for requirement ``typing_extensions`` to ensure compatibility.

v0.6.0 (2024-03-17)
-------------------
* Drop support for Python 3.7, as it is end-of-life since June 2023. The minimum required version is now 3.8.
* Changed some arguments of some methods to keyword-only arguments. This is a backwards-incompatible change.

* Added support for Python 3.12.
* Fix support for pyasn1 v0.5.1 and later
* Added full typing support, with full and complete type annotations.
* Added ``multi_verify_mode`` as argument to ``SignedPEFile.verify``. This allows you to specify how you'd like to
  handle the case of multiple signatures in the PE file, but not all signatures validate. The Windows default seems to
  be to rely on the first signature, though Signify defaults to allow any signature to verify. Next to these two,
  we have also added the options for 'all' (all signatures must verify) and 'best' (the best must verify).

v0.5.2 (2023-04-22)
-------------------
* Pin pyasn1 dependency version to <0.5.0 for now, due to some apparent backwards-incompatible changes.

v0.5.1 (2023-03-22)
-------------------
* Remove PyInstaller hook and optional requirements from setup.py

v0.5.0 (2023-03-20)
-------------------
* Drop support for Python 3.6
* Add support for ECC keys
* Move certificates to a separate project, `mscerts <https://pypi.org/project/mscerts/>`_,
  so that we can update it separately
* Fix DisallowedFileTime check in Authroot parsing to ensure it checks against the DisallowedFileTime and not the
  NotbeforeTime.
* Fix parsing of ``Certificate.subject_public_key`` to ensure it returns a proper bytestring
* Fix return statement of ``RFC3161SignedData.verify`` to return True.

v0.4.0 (2021-08-23)
-------------------
The following backwards incompatible changes were made:

* Drop support for Python 3.5
* Moved some stuff around to make more clear packages: ``signify.fingerprinter`` will remain unchanged,
  ``signify.x509`` combines certificates and their verification, ``signify.pkcs7`` combines SignedData and SignerInfo,
  and ``signify.authenticode`` contains all Microsoft-related code. This change is also reflected in how the docs
  are structured.
* Changed ``AuthenticodeSignedData.verify`` to accept ``countersignature_mode`` as an argument, replacing
  ``allow_countersignature_errors``. This allows you to skip countersignatures entirely, allowing actually using CRL
  checks (otherwise, a timestamp would be set on the context of validation, which results in certvalidator disallowing
  the CRL check because it cannot work with both timestamps and CRLs).
* Changed ``CertificateStore.verify_trust``, ``VerificationContext.verify_trust`` and
  ``CertificateTrustList.verify_trust`` to accept a certificate chain instead of a single certificate. This allows us
  to check end-entity certificates in ``CertificateTrustList``.
* ``CertificateTrustSubject.is_valid`` has been removed.

The following features were added and bugs were fixed:

* Added the functions ``explain_verify`` to ``SignedPEFile`` and ``AuthenticodeSignerInfo`` that return an
  easy-to-digest enum with the verification result.
* Added support for nested SignedData structures inside the unauthenticated attributes of SignerInfo objects. These
  are transparently added to the ``SignedPEFile.signed_datas`` iterator. You can use ``SignedPEFile.iter_signed_datas``
  to control this behaviour.
* By default, now uses a properly parsed Microsoft ``CertificateTrustList`` to allow partial removal of some
  certificates from the store, fixing a bug with our original implementation. This aligns with the implementation on
  Windows, and allows Microsoft to remove untrusted certificates from a certain timestamp, or to only allow certain
  EKU's. To restore original behaviour, use ``TRUSTED_CERTIFICATE_STORE_NO_CTL`` as certificate store.
* Fixed issue where an abnormal order in the authenticated attributes of SignerInfo objects would cause validation to
  fail.

v0.3.0 (2020-08-16)
-------------------
This release should be mostly backwards-compatible, but various features have been added that warranted a larger
version increase.

* Support for passing in a different trusted certificate store than the default in various verify functions
* Added option to ignore countersignature errors when validating
* Added support for SHA-384 and SHA-512
* Added ``Certificate.from_pems``, ``Certificate.__hash__``, ``Certificate.sha1_fingerprint``,
  ``Certificate.sha256_fingerprint``
* Added ``CertificateStore.find_certificate`` and ``CertificateStore.find_certificates``
* Added support for ``authroot.stl`` (``signify.authroot``), though we haven't figured out how it works exactly yet.
  Support can be used by adding a ctl to a trusted ``CertificateStore``.
* Updated authenticode certificate store by basing it on Microsoft's ``authroot.stl``
* Fixed bug in RFC3161 countersignatures that contain malformed RFC5652 structures
* Fixed bug in RFC3161 countersignatures that have a different digest function and hash function

v0.2.0 (2020-04-27)
-------------------
This release contains various backwards-incompatible changes.

* Fix error that SpcSpOpusInfo was considered required
* Fix error that CounterSignerInfo would require a specific content type
* Fix error that countersignatures could be present as entire RFC3161 responses
* Add option to process CRL checks and OCSP responses
* Change to use the module pyasn1-modules instead of own ASN.1 classes
* Change issuer/subject to a specific class

v0.1.5 (2019-03-16)
-------------------
* Resolve error that would cause in infinite loops in parsing of the authenticode certtable (contributed by wtfuzz)

v0.1.4 (2018-12-15)
-------------------
* Prevent iterating over duplicate certificates
* Fix bug where some samples would not be recognized as signed
* Add support for sha256 hashes
* Fix bug where countersignature verification would use the wrong digest algorithm
* Add a lot more built-in certificates
* Fix some error-handling and reporting

v0.1.3 (2018-12-15)
-------------------
* Increase minimum Python to 3.5
* Adjust location of certificate store and ensure it is included
* Add option to get a list of all potential chains
* Add option to get components of a issuer/subject

v0.1.2 (2018-03-25)
-------------------
* Change from using cryptography to using certvalidator
* Rewrite of validation routines

v0.1.1 (2018-03-25)
-------------------
* Rename to Signify
* Modify how trust is determined in a certificate store

v0.1 (2018-03-18)
-----------------
Initial release