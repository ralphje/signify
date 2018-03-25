Signify documentation
=====================
Signify, a portmanteau of *signature* and *verify*, is a Python module that computers and validates signatures.
At this point it is mostly a library that verifies PE Authenticode-signed binaries.

This module is a forked from Google's ``verify_sigs`` module, updated to fit
modern Python standards and be compatible with Python 3. It is **not** a drop-in
replacement, as significant changes have occurred.

This module is compatible with Python 3.4+ and does not support Python 2.

.. toctree::
   :maxdepth: 2
   :caption: Python interface

   fingerprinter
   certificates
   authenticode



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

