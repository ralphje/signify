Signify
=======
.. image:: https://travis-ci.org/ralphje/signify.svg?branch=master
    :target: https://travis-ci.org/ralphje/signify
.. image:: https://codecov.io/gh/ralphje/signify/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/ralphje/signify
.. image:: https://readthedocs.org/projects/signify/badge/?version=latest
    :target: http://signify.readthedocs.io/en/latest/?badge=latest

Signify, a portmanteau of *signature* and *verify*, is a Python module that computers and validates signatures.
At this point it is mostly a library that verifies PE Authenticode-signed binaries.

This module is a forked from Google's ``verify_sigs`` module, updated to fit
modern Python standards and be compatible with Python 3. It is **not** a drop-in
replacement, as significant changes have occurred.

This module is compatible with Python 3.4+ and does not support Python 2.

Installation
------------
Installation is very simple::

    pip install signify

Documentation
-------------
Documentation is available at http://signify.readthedocs.io/en/latest/ or in the docs/ directory.

Thanks
------
Thanks to Germano Caronni (caronni@google.com, gec@acm.org) for writing the basis of this module.
