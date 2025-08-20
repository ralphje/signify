Authenticode
============
.. module:: signify.authenticode

The Authenticode support of Signify allows you to easily verify a PE or MSI File's
Authenticode signature::

    with open("file.exe", "rb") as f:
        signed_file = AuthenticodeFile.from_stream(f)
        signed_file.verify()

This method will raise an error if it is invalid. A simpler API is also available,
allowing you to interpret the error if one happens::

    with open("file.exe", "rb") as f:
        signed_file = AuthenticodeFile.from_stream(f)
        status, err = signed_file.explain_verify()

    if status != AuthenticodeVerificationResult.OK:
        print(f"Invalid: {err}")

If you need to get more information about the signature, you can use this::

    with open("file.exe", "rb") as f:
        signed_file = AuthenticodeFile.from_stream(f)
        for signed_data in signed_file.signatures:
            print(signed_data.signer_info.program_name)
            if signed_data.signer_info.countersigner is not None:
                print(signed_data.signer_info.countersigner.signing_time)

A more thorough example is available in the examples directory of the Signify
repository.

Note that the file must remain open as long as not all SignedData objects have been
parsed or verified.

Authenticode overview
---------------------
Most of the specification of Authenticode as applied to Portable Executables (normal
Windows executables) is documented in a 2008 paper
`Windows Authenticode Portable Executable Signature Format <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_
and still available to download. The specification mostly follows the :doc:`pkcs7`
specification, although most structures have since been updated in more recent RFCs. Of
particular note is that the specification defines various *"must"* and *"must not"*
phrases, which has not been adhered to in more recent uses.

At its core, the paper defines how the certificate table of a PE file contains PKCS#7
SignedData objects. Note that the specification allows for multiple of such objects,
perhaps including other signers or signatures. Authenticode SignedData objects contain
'indirect data' (*microsoft_spc_indirect_data_content*, OID ``1.3.6.1.4.1.311.2.1.4``),
which (amongst others) defines the hash of the signed file.

The signed file must be hashed in particular way, as we want to make sure to exclude the
signature itself from the hash, as that would alter the hash. In the case of PE files,
this means that the certificate table in the data directory is ignored, as the file's
checksum. The signature is valid, in principle, if the hash we calculate is the same as
in the indirect data (and the ``SignedData`` verifies as well).

Although the paper does not go into this in further detail, Subject Interface Packages
(SIPs), can define a similar approach to various other file types, such as MSI files
or CAB files. See :doc:`authenticode_files` for more information on this.

There are various other requirements, such as that the signing certificate must have
the *code_signing* extended key usage (OID ``1.3.6.1.5.5.7.3.3``) and that none of the
certificates in the signing chain can be untrusted. For more information about the
inner workings of Microsoft's certificate chains, see :doc:`authroot`.

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

There are a few additional gotcha's when verifying Authenticode signatures, which are
not very well defined in the original specification, but we have been able to
reverse-engineer or otherwise use to our advantage.

RFC3161 countersignatures
#########################
There are two types of countersignature: a regular countersignature, as used in PKCS#7,
or a nested Time-Stamp Protocol response (RFC3161). This response, available as
unauthenticated attribute with *microsoft_time_stamp_token* (OID
``1.3.6.1.4.1.311.3.3.1``), is added as nested :class:`authenticode.pkcs7.SignedData`
object.

This is transparently handled by the :attr:`AuthenticodeSignature.countersigner`
attribute, but note that this attribute can return two different types.

Nested signatures
#################
Instead of adding multiple signatures to the certificate table, SignedData objects
can also be nested in others as unauthenticated attributes with
*microsoft_nested_signature* (OID ``1.3.6.1.4.1.311.2.4.1``).

This is transparently handled by the
:meth:`AuthenticodeSignature.iter_recursive_nested` and
:meth:`AuthenticodeFile.iter_embedded_signatures` (with ``included_nested=True``)
methods.

Additional attributes and extensions
####################################
Some attributes are present on SignerInfo objects that have additional meanings:

*microsoft_spc_sp_opus_info* (``1.3.6.1.4.1.311.2.1.12``)
   Contains the program name and URL
*microsoft_spc_statement_type* (``1.3.6.1.4.1.311.2.1.11``)
   Defines that the key purpose is individual (``1.3.6.1.4.1.311.2.1.21``) or
   commercial (``1.3.6.1.4.1.311.2.1.22``), but unused in practice.
*microsoft_spc_relaxed_pe_marker_check* (``1.3.6.1.4.1.311.2.6.1``)
   Purpose unknown
*microsoft_platform_manifest_binary_id* (``1.3.6.1.4.1.311.10.3.28``)
   Purpose unknown

For certificates, these extensions are known:

*microsoft_spc_sp_agency_info* (``1.3.6.1.4.1.311.2.1.10``)
   Purpose unknown
*microsoft_spc_financial_criteria* (``1.3.6.1.4.1.311.2.1.27``)
   Purpose unknown

The following key purpose is relevant for Authenticode:

*microsoft_lifetime_signing* (``1.3.6.1.4.1.311.10.3.13``)
   The certificate is only valid for it's lifetime, and cannot be extend with a counter
   signature.

All these attributes and extensions are defined in the ASN.1 spec of this library,
but not all of them are used.

Future work:

* ``1.3.6.1.4.1.311.2.5.1`` (*enhanced_hash*)

Authenticode-signed File Objects
--------------------------------
The basic interface to Authenticode-signed files is
:meth:`AuthenticodeFile.from_stream`. This will make sure that a concrete
implementation, such as :class:`signify.authenticode.signed_file.SignedPeFile` or
:class:`signify.authenticode.signed_file.SignedMsiFile` will be returned, implementing
the same interface.

This generic interface allows access to zero or more :class:`AuthenticodeSignature`
objects, and allows validation of the signature.

.. autoclass:: AuthenticodeFile
   :members:

.. autoclass:: AuthenticodeVerificationResult
   :members:
