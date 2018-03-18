Authenticode
============


Signed PE File
--------------
.. module:: pesigcheck.signed_pe

.. autoclass:: SignedPEFile
   :members:


.. module:: pesigcheck.authenticode

Data structures
---------------
.. autoclass:: SignedData
   :members:
.. autoclass:: Certificate
   :members:
.. autoclass:: SignerInfo
   :members:
.. autoclass:: CounterSignerInfo
   :members:
.. autoclass:: SpcInfo
   :members:

Verification
------------
.. autoclass:: VerificationContext
   :members:
.. autoclass:: CertificateStore
   :members:
.. autoclass:: FileSystemCertificateStore
   :members:

Exceptions
----------
.. autoclass:: AuthenticodeParseError
   :members:
.. autoclass:: AuthenticodeVerificationError
   :members:

