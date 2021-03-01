=========================
SignedData and SignerInfo
=========================

To support Authenticode, this library includes some code to parse and validate SignedData structures. These are defined
in several RFC's, most notably RFC2315 (which is the version Authenticode uses). The structure of all relevant RFC's
follow ASN.1 notation to define the relevant structures. These definitions are not always easily digested, but it does
show which fields are available.

This chapter of the documentation shows how these basic structures work, so we can dive deep into their operations
in the next chapter.

The following diagram shows the relation between SignedData and SignerInfo:

.. image:: https://yuml.me/8e9c7bb6.svg

Note that although this diagram is not very complicated, when discussing Authenticode, we will be creating multiple
SignedData and SignerInfo structures, nested in each other, so it's important to fully understand this structure.

SignedData
==========
The SignedData object is the root structure for sending encrypted data in PKCS#7.

.. module:: signify.signeddata

.. autoclass:: SignedData
   :members:

SignerInfo
==========

.. module:: signify.signerinfo

.. autoclass:: SignerInfo
   :members:

CounterSignerInfo
=================

.. autoclass:: CounterSignerInfo
   :members:
