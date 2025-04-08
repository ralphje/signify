Signify
=======
.. image:: https://github.com/ralphje/signify/actions/workflows/test.yml/badge.svg
    :target: https://github.com/ralphje/signify/actions/workflows/test.yml
.. image:: https://codecov.io/gh/ralphje/signify/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/ralphje/signify
.. image:: https://readthedocs.org/projects/signify/badge/?version=latest
    :target: http://signify.readthedocs.io/en/latest/?badge=latest

Signify, a portmanteau of *signature* and *verify*, is a Python module that computes and validates signatures.
At this point it is mostly a library that verifies PE Authenticode-signed binaries.

This module is a forked from Google's ``verify_sigs`` module, updated to fit
modern Python standards and be compatible with Python 3. It is **not** a drop-in
replacement, as significant changes have occurred.

This module is compatible with Python 3.9+.

Installation
------------
Installation is very simple::

    pip install signify

MSI file support requires::

    pip install signify[msi]

Documentation
-------------
Documentation is available at http://signify.readthedocs.io/en/latest/ or in the docs/ directory.

Thanks
------
Thanks to Germano Caronni (caronni@google.com, gec@acm.org) for writing the basis of this module.
