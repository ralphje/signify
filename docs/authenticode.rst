Authenticode
============
The Authenticode support of Signify allows you to easily verify a PE File's signature::

    with open("file.exe", "rb") as f:
        pefile = SignedPEFile(f)
        pefile.verify()

This method will raise an error if it is invalid. If you need to get more information about the signature, you
can use this::

    with open("file.exe", "rb") as f:
        pefile = SignedPEFile(f)
        for signed_data in pefile.signed_datas:
            print(signed_data.signer_info.program_name)

Note that the file must remain open as long as nog all SignedData objects have been parsed.

Signed PE File
--------------
A regular PE file will contain zero or one :class:`AuthenticodeSignedData` objects. The :class:`SignedPEFile` class
contains helpers to ensure the correct objects can be extracted, and additionally, allows for validating the PE
signatures.

.. module:: signify.signed_pe

.. autoclass:: SignedPEFile
   :members:

SignedData and SignerInfo
-------------------------
To help understand the specific SignedData and SignerInfo objects, the following graph may help:

.. image:: http://yuml.me/f68f2b83.svg

.. module:: signify.authenticode

.. autoclass:: AuthenticodeSignedData
   :members:

.. autoclass:: SpcInfo
   :members:

.. autoclass:: AuthenticodeSignerInfo
   :members:

Regular countersigning
----------------------

.. autoclass:: AuthenticodeCounterSignerInfo
   :members:

RFC3161 countersigning
----------------------

.. autoclass:: RFC3161SignedData
   :members:
.. autoclass:: TSTInfo
   :members:
.. autoclass:: RFC3161SignerInfo
   :members:


