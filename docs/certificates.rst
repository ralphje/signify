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

   .. attribute:: data

      The underlying ASN.1 data object

   .. attribute:: signature_algorithm
   .. attribute:: signature_value
   .. attribute:: version
   .. attribute:: serial_number
   .. attribute:: issuer
   .. attribute:: issuer_dn
   .. attribute:: valid_from
   .. attribute:: valid_to
   .. attribute:: subject
   .. attribute:: subject_dn
   .. attribute:: subject_public_algorithm
   .. attribute:: subject_public_key
   .. attribute:: extensions

SignerInfo
----------
.. module:: signify.signerinfo

.. autoclass:: SignerInfo
   :members:

   .. attribute:: data

      The underlying ASN.1 data object

   .. attribute:: issuer
   .. attribute:: issuer_dn
   .. attribute:: serial_number
   .. attribute:: digest_algorithm
   .. attribute:: authenticated_attributes
   .. attribute:: message_digest
   .. attribute:: content_type
   .. attribute:: signing_time
   .. attribute:: digest_encryption_algorithm
   .. attribute:: encrypted_digest
   .. attribute:: unauthenticated_attributes
   .. attribute:: countersigner

      The :class:`CounterSignerInfo` object.


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
