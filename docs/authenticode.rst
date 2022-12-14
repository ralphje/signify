Authenticode
============
.. module:: signify.authenticode

The Authenticode support of Signify allows you to easily verify a PE File's signature::

    with open("file.exe", "rb") as f:
        pefile = SignedPEFile(f)
        pefile.verify()

This method will raise an error if it is invalid. A simpler API is also available, allowing you to interpret the error
if one happens::

    with open("file.exe", "rb") as f:
        pefile = SignedPEFile(f)
        status, err = pefile.explain_verify()

    if status != AuthenticodeVerificationResult.OK:
        print(f"Invalid: {err}")

If you need to get more information about the signature, you can use this::

    with open("file.exe", "rb") as f:
        pefile = SignedPEFile(f)
        for signed_data in pefile.signed_datas:
            print(signed_data.signer_info.program_name)
            if signed_data.signer_info.countersigner is not None:
                print(signed_data.signer_info.countersigner.signing_time)

A more thorough example is available in the examples directory of the Signify repository.

Note that the file must remain open as long as not all SignedData objects have been parsed.

Signed PE File
--------------
A regular PE file will contain zero or one :class:`AuthenticodeSignedData` objects. The :class:`SignedPEFile` class
contains helpers to ensure the correct objects can be extracted, and additionally, allows for validating the PE
signatures.

.. autoclass:: SignedPEFile
   :members:

.. autoclass:: AuthenticodeVerificationResult
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
The countersignature is used to verify the timestamp of the signature. This is usually done by sending the signature
to a time-stamping service, that provides the countersignature. This allows the signature to continue to be valid, even
after the original certificate chain expiring.

There are two types of countersignature: a regular countersignature, as used in PKCS7, or a nested RFC3161 response.
This nested object is basically a :class:`authenticode.pkcs7.SignedData` object, which holds its own set of
certificates.

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
