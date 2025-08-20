Additional Authenticode Structures
==================================

PKCS#7 objects
--------------
To help understand the specific SignedData and SignerInfo objects, the following graph
may help:

.. image:: http://yuml.me/f68f2b83.svg

.. autoclass:: signify.authenticode.AuthenticodeSignature
   :members:
   :special-members: __init__

.. autoclass:: signify.authenticode.indirect_data.IndirectData
   :members:
.. autoclass:: signify.authenticode.indirect_data.PeImageData
   :members:
.. autoclass:: signify.authenticode.indirect_data.SigInfo
   :members:

.. autoclass:: signify.authenticode.signer_info.AuthenticodeSignerInfo
   :members:

Countersignature
----------------
The countersignature is used to verify the timestamp of the signature. This is usually
done by sending the signature to a time-stamping service, that provides the
countersignature. This allows the signature to continue to be valid, even
after the original certificate chain expiring.

There are two types of countersignature: a regular countersignature, as used in PKCS7,
or a nested RFC3161 response. This nested object is basically a
:class:`authenticode.pkcs7.SignedData` object, which holds its own set of certificates.

Regular
~~~~~~~

.. autoclass:: signify.authenticode.signer_info.AuthenticodeCounterSignerInfo
   :members:

RFC3161
~~~~~~~

.. autoclass:: signify.authenticode.tsp.RFC3161SignedData
   :members:
.. autoclass:: signify.authenticode.tsp.TSTInfo
   :members:
.. autoclass:: signify.authenticode.tsp.RFC3161SignerInfo
   :members:
