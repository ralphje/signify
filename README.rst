Signify
=======
.. image:: https://github.com/ralphje/signify/actions/workflows/test.yml/badge.svg
    :target: https://github.com/ralphje/signify/actions/workflows/test.yml
.. image:: https://codecov.io/gh/ralphje/signify/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/ralphje/signify
.. image:: https://readthedocs.org/projects/signify/badge/?version=latest
    :target: http://signify.readthedocs.io/en/latest/?badge=latest

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

Installation
------------
Installation is very simple::

    pip install signify

Support for some file types (including MSI) requires::

    pip install signify[full]

Documentation
-------------
Documentation is available at http://signify.readthedocs.io/en/latest/ or in the docs/
directory.

Thanks
------
Huge thanks to Germano Caronni for writing the original code in the
`verify_sigs project <https://github.com/anthrotype/verify-sigs>`_, on which this
project was based.

A multitude of significant improvements and modifications was made on top of their
original contribution, including improving PE signature support, adding support for
various other files, and moving the original scripts into a modern Python module.
