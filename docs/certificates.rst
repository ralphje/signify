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
                  signature_value
                  subject_public_algorithm
                  subject_public_key

      These values are considered part of the certificate, but not
      fully parsed.

   .. attribute:: version

      This is the version of the certificate

   .. attribute:: serial_number

      The full integer serial number of the certificate

   .. attribute:: issuer
                  subject

      The :class:`CertificateName` for the issuer and subject.

   .. attribute:: valid_from
                  valid_to

      The datetime objects between which the certificate is valid.

   .. attribute:: extensions

      This is a list of extension objects.

.. autoclass:: CertificateName
   :members:

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
