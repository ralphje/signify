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
.. module:: signify.signed_pe

.. autoclass:: SignedPEFile
   :members:


.. module:: signify.authenticode

Data structures
---------------
.. autoclass:: SignedData
   :members:

   .. attribute:: data

      The underlying ASN.1 data object

   .. attribute:: pefile

      The underlying :class:`signify.signed_pe.SignedPEFile` object

   .. attribute:: digest_algorithm
   .. attribute:: content_type
   .. attribute:: spc_info

      The :class:`SpcInfo` object.

   .. attribute:: certificates

      The :class:`signify.context.CertificateStore` object.

   .. attribute:: signer_info

      The :class:`AuthenticodeSignerInfo` object.

.. autoclass:: AuthenticodeSignerInfo
   :members:

   .. attribute:: program_name
   .. attribute:: more_info

.. autoclass:: AuthenticodeCounterSignerInfo
   :members:
.. autoclass:: SpcInfo
   :members:

   .. attribute:: data

      The underlying ASN.1 data object

   .. attribute:: content_type

      The contenttype class

   .. attribute:: image_data
   .. attribute:: digest_algorithm
   .. attribute:: digest
   .. attribute:: image_data




