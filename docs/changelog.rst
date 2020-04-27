Release notes
=============
This page contains the most significant changes in Signify between each release.

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