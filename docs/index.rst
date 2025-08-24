Signify documentation
=====================
Signify, a portmanteau of *signature* and *verify*, is a Python module that provides
validation and inspection of digital code signatures. These types of signatures are
used to verify the authenticity and integrity of executable code, providing assurance
about who published a piece of software and whether is has been altered since it was
signed.

This library is mostly intended for malware analysts and security professionals to
allow validation of these signatures outside their normal ecosystem and enable close
inspection of the available data.

Currently, this library is only able to verify Windows Authenticode signatures, the
specific Microsoft technology that is used in Windows to verify software integrity.
Typically, Authenticode signatures are embedded into the file itself, without altering
the functionality of the software. However, these signatures can also be provided by
external Authenticode catalogs (.cat files), allowing virtually any file to be signed
using this technology.

The following file types are supported, with support for other file types being
expected:

* PE executables (.exe, .dll and various other Windows executables)
* MSI files (.msi)
* Catalog files (.stl and .cat)
* Any flat file that is signed through a catalog file

This module is compatible with Python 3.9+.

.. toctree::
   :maxdepth: 1

   changelog

.. toctree::
   :maxdepth: 2
   :caption: Generic objects

   fingerprinter
   certificates
   pkcs7


.. toctree::
   :maxdepth: 2
   :caption: Authenticode

   authenticode
   authenticode_files
   authroot
   authenticode_structures
   authenticode_asn1


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

