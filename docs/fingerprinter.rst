Fingerprinter
=============

.. module:: signify.fingerprinter

The fingerprinter is a simple module that allows you to apply multiple hashes in a
single run. It is intended to be used as follows::

   >>> with open("file", "rb") as f:
   ...     fingerprinter = Fingerprinter(file_obj)
   ...     fingerprinter.add_hashers(hashlib.sha1, hashlib.sha256)
   ...     print(fingerprinter.hash())

   {"sha1": ..., "sha256": ...}

However, you can also use it to calculate PE Authenticode hashes as follows::

   >>> with open("file", "rb") as f:
   ...     fingerprinter = SignedPEFingerprinter(file_obj)
   ...     fingerprinter.add_signed_pe_hashers(hashlib.sha1, hashlib.sha256)
   ...     print(fingerprinter.hash())

   {"sha1": ..., "sha256": ...}

You can also combine these for more efficiency::

   >>> with open("file", "rb") as f:
   ...     fingerprinter = SignedPEFingerprinter(file_obj)
   ...     fingerprinter.add_hashers(hashlib.sha1, hashlib.sha256)
   ...     fingerprinter.add_signed_pe_hashers(hashlib.sha1, hashlib.sha256)
   ...     print(fingerprinter.hashes())

   {"generic": {"sha1": ..., "sha256": ...},
    "authentihash": {"sha1": ..., "sha256": ...}}

You probably only need access to these classes:

.. autoclass:: Fingerprinter
   :members:
   :special-members: __init__

The following interfaces are also available:

.. autoclass:: Range
.. autoclass:: Finger
   :members:
   :special-members: __init__
