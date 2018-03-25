Certificates and SignerInfo
===========================
Signify has two generic x509 structures: SignerInfo and Certificate. The Certificate is an object that abstracts
a x509 certificate and has the ability to be verified. The SignerInfo is also a x509 object that can be verified.

Note that SignedData is not (yet) a generic structure.

You can use this module as follows::

   trust_store = FileSystemCertificateStore(location=pathlib.Path("certificates/authenticode/"), trusted=True)
   context = VerificationContext(trust_store)
   with open("certificate.pem", "rb") as f, open("certificate2.pem", "rb") as g:
       to_verify1 = Certificate.from_pem(f.read())
       to_verify2 = Certificate.from_pem(g.read())

   to_verify1.verify(context)  # prints True
   to_verify2.verify(context)  # raises VerificationError

Certificate
-----------
.. module:: signify.certificates

.. autoclass:: Certificate
   :members:

SignerInfo
----------
.. module:: signify.signerinfo

.. autoclass:: SignerInfo
   :members:
.. autoclass:: CounterSignerInfo
   :members:

Verification
------------

.. module:: signify.context

.. autoclass:: VerificationContext
   :members:
.. autoclass:: CertificateStore
   :members:
.. autoclass:: FileSystemCertificateStore
   :members:
