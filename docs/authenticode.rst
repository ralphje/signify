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

A more thorough example is available in the examples directory of the Signify
repository.

Note that the file must remain open as long as not all SignedData objects have been
parsed or verified.

Authenticode overview
---------------------
Most of the specification of Authenticode is properly documented in a 2008 paper
`Windows Authenticode Portable Executable Signature Format <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_
and still available to download. The specification mostly follows the :doc:`pkcs7`
specification, although most structures have since been updated in more recent RFCs. Of
particular note is that the specification defines various "must" and "must not"
phrases, which has not been adhered to in more recent uses.

At its core, it defines how the certificate table of a PE file (a normal Windows
executable) contains PKCS#7 SignedData objects. Note that the specification allows for
multiple of such objects, perhaps including other signers or signatures.

Authenticode SignedData objects contain ``SpcIndirectDataContent`` contents
(microsoft_spc_indirect_data_content, OID 1.3.6.1.4.1.311.2.1.4), which
(amongst others) define the hash of the PE file. The
PE file is hashed particularly, as we need to skip the PE file checksum, the
pointer to the certificate table in the data directory, and the certificate table
itself.

The signature is valid, in principle, if the hash we calculate is the same as in
``SpcIndirectDataContent``, and the ``SignerInfo`` contains a hash over this content.

.. seealso::

   There are various other projects that also deal with Authenticode, which also
   provide useful insights. These include:

   * `μthenticode <https://blog.trailofbits.com/2020/05/27/verifying-windows-binaries-without-windows/>`_
   * `LIEF <https://lief.re/doc/latest/tutorials/13_pe_authenticode.html>`_
   * `osslsigncode <https://github.com/mtrojnar/osslsigncode>`_
   * `winsign <https://github.com/mozilla-releng/winsign>`_
   * `AuthenticodeLint <https://github.com/vcsjones/AuthenticodeLint>`_
   * `jsign <https://github.com/ebourg/jsign>`_

   Other useful references include:

   * `Windows Authenticode Portable Executable Signature Format <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_
   * `Caveats for Authenticode Signing <https://learn.microsoft.com/en-us/archive/blogs/ieinternals/caveats-for-authenticode-code-signing>`_

Additional gotcha's
~~~~~~~~~~~~~~~~~~~
There are a few additional gotcha's when verifying Authenticode signatures, which are
not very well defined in the original specification, but we have been able to
reverse-engineer or otherwise use to our advantage.

RFC3161 countersignatures
#########################
There are two types of countersignature: a regular countersignature, as used in PKCS#7,
or a nested Time-Stamp Protocol response (RFC3161). This response, available as
unauthenticated attribute with microsoft_time_stamp_token (OID 1.3.6.1.4.1.311.3.3.1),
is added as nested :class:`authenticode.pkcs7.SignedData` object.

This is transparently handled by the :attr:`AuthenticodeSignedData.countersigner`
attribute, but note that this attribute can return two different types.

Nested signatures
#################
Instead of adding multiple signatures to the certificate table, SignedData objects
can also be nested in others as unauthenticated attributes with
microsoft_nested_signature (OID 1.3.6.1.4.1.311.2.4.1).

This is transparently handled by the :class:`SignedPEFile` class.

Page hashes
###########
The ``SpcIndirectDataContent`` class may contain a binary structure that defines
hashes for portions of the file (in the ``SpcLink.moniker`` field). If this is the case,
the moniker will use class ID ``a6b586d5-b4a1-2466-ae05-a217da8e60d6``, and its
serialized data will contain another ``SpcAttributeTypeAndOptionalValue`` with OIDs
microsoft_spc_pe_image_page_hashes_v1 (1.3.6.1.4.1.311.2.3.1) for SHA-1 or
microsoft_spc_pe_image_page_hashes_v2 (1.3.6.1.4.1.311.2.3.2) for SHA-256.

The value will be a binary structure that describes offsets (4 bytes integer) and
hash digest (digest length of the algorithm) of parts of the binary. These offsets
appear to be relative to the entire file, and the final offset is always at the end
of the file (describing the end of the previous hash), and the final hash is ignored::

    0000000  08d88d96cb3fddf7a7c73598e95388ce60432c2c5ff17b8c558ce599645db73e
    0001024  5ebe1d0255524e4291105759b80abad8294e269e3e11fce76ed6b2e005a79df0
    0005120  255d7a5768ac44963184e0b5281d64fd9282f953211d03fd49a3d8190044dc35
    ...
    1436160  35c36ac4c657e82cc3aa1311373c1b17552780f64e000a2c31742125365145cd
    1438720  0000000000000000000000000000000000000000000000000000000000000000

Each hash is then calculated between the two defined offsets, using the same omissions
as for normal Authenticode validation. The hashes are filled with NULL bytes when the
hash would be shorter than the page size (typically 4096), ignoring omissions.

In the example above, for the first hash, we would calculate the hash over the first
1024 bytes of the PE file, skipping the checksum and table locations located in the
PE header file, and then add 3072 NULL bytes to complete a full PE page. Note that the
actual digest is calculated over less than 4096 bytes due to the omissions.

Additional attributes, extensions
#################################
Some attributes are present on SignerInfo objects that have additional meanings:

microsoft_spc_sp_opus_info (1.3.6.1.4.1.311.2.1.12)
   Contains the program name and URL
microsoft_spc_statement_type (1.3.6.1.4.1.311.2.1.11)
   Defines that the key purpose is individual (1.3.6.1.4.1.311.2.1.21) or
   commercial (1.3.6.1.4.1.311.2.1.22), but unused in practice.
microsoft_spc_relaxed_pe_marker_check (1.3.6.1.4.1.311.2.6.1)
   Purpose unknown
microsoft_platform_manifest_binary_id (1.3.6.1.4.1.311.10.3.28)
   Purpose unknown

For certificates, these extensions are known:

microsoft_spc_sp_agency_info (1.3.6.1.4.1.311.2.1.10)
   Purpose unknown
microsoft_spc_financial_criteria (1.3.6.1.4.1.311.2.1.27)
   Purpose unknown

The following key purpose is relevant for Authenticode:

microsoft_lifetime_signing (1.3.6.1.4.1.311.10.3.13)
   The certificate is only valid for it's lifetime, and cannot be extend with a counter
   signature.

All these attributes and extensions are defined in the ASN.1 spec of this library,
but not all of them are used.

Future work:

* 1.3.6.1.4.1.311.2.5.1 (enhanced_hash)

Signed PE File
--------------
A regular PE file will contain zero or one :class:`AuthenticodeSignedData` objects.
The :class:`SignedPEFile` class contains helpers to ensure the correct objects can be
extracted, and additionally, allows for validating the PE signatures.

.. autoclass:: SignedPEFile
   :members:

.. autoclass:: AuthenticodeVerificationResult
   :members:

PKCS7 objects
-------------
To help understand the specific SignedData and SignerInfo objects, the following graph
may help:

.. image:: http://yuml.me/f68f2b83.svg

.. autoclass:: AuthenticodeSignedData
   :members:

.. autoclass:: SpcInfo
   :members:

.. autoclass:: AuthenticodeSignerInfo
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
