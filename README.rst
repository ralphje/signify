pesigcheck
==========
.. image:: https://travis-ci.org/ralphje/pesigcheck.svg?branch=master
    :target: https://travis-ci.org/ralphje/pesigcheck
.. image:: https://codecov.io/gh/ralphje/pesigcheck/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/ralphje/pesigcheck
.. image:: https://readthedocs.org/projects/pesigcheck/badge/?version=latest
    :target: http://pesigcheck.readthedocs.io/en/latest/?badge=latest

pesigcheck is a Python module to compute and validate hashes on different file
types, mostly aimed at computing PE Authenticode-signed binaries.

This module is a forked from Google's ``verify_sigs`` module, updated to fit
modern Python standards and be compatible with Python 3. It is **not** a drop-in
replacement, as significant changes have occurred.

This module is not made for compatibility with Python 2.x

Thanks
------
Thanks to Germano Caronni (caronni@google.com, gec@acm.org) for writing the
basis of this module. 

