===================================
X509: Certificates and Verification
===================================
.. module:: signify.x509

To be able to verify structures, Signify has a library to allow validating certificates. The Certificate is an object
that abstracts a x509 certificate and has the ability to be verified. The verification requires the creation of a
validation chain, that lead back to a trusted certificate authority.

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

.. autoclass:: Certificate
   :members:

.. autoclass:: CertificateName
   :members:

Certificate Store
-----------------
.. autoclass:: CertificateStore
   :members:
   :special-members: __init__
.. autoclass:: FileSystemCertificateStore
   :members:
   :special-members: __init__

Verification
------------

.. autoclass:: VerificationContext
   :members:
   :special-members: __init__
