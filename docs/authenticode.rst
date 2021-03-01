Authenticode
============
.. module:: signify.authenticode

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

.. autoclass:: SignedPEFile
   :members:

PKCS7 objects
-------------
To help understand the specific SignedData and SignerInfo objects, the following graph may help:

.. image:: http://yuml.me/f68f2b83.svg

.. autoclass:: AuthenticodeSignedData
   :members:

.. autoclass:: SpcInfo
   :members:

.. autoclass:: AuthenticodeSignerInfo
   :members:

Countersignature
----------------

Regular
~~~~~~~

.. autoclass:: AuthenticodeCounterSignerInfo
   :members:

RFC3161
~~~~~~~

.. autoclass:: RFC3161SignedData
   :members:
.. autoclass:: TSTInfo
   :members:
.. autoclass:: RFC3161SignerInfo
   :members:

Certificate Trust Lists (authroot.stl)
--------------------------------------
Microsoft distributes its own Certificate Trust Lists, containing all trusted certificates. More information about its
root program can be found
`on Microsoft's website <https://docs.microsoft.com/en-us/security/trusted-root/release-notes>`_. Unfortunately, the
exact meaning of certificates in the store with respect to Authenticode, is as of yet unclear.

.. autoclass:: CertificateTrustList
   :members:
.. autoclass:: CertificateTrustSubject
   :members:
