====================
Supported File Types
====================
.. module:: signify.authenticode.signed_file

Various file types in Windows support Authenticode. For each file type, Windows must
know how to create a unique digest of the file, and how to extract the embedded
Authenticode signature from the file, and verify that those two match. This can get
quite complicated; for instance, with PE executable files, the digest should not include
the embedded signature itself, nor the checksum, as those would alter the signature.

Subject Interface Packages (SIPs)
=================================
To let Windows know how to create, store, retrieve, and verify a signature, specific
Windows APIs called Subject Interface Packages (SIPs) are used. Each file type (subject)
as a different SIP, i.e. typically a different DLL, that instruments Windows on these
types of actions.

While Windows ships with a default set of SIPs, it is possible to create and register
SIPs for any file type. All SIP methods are registered in registry key
``HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0``. The default ones are:

================================  ======================================  ============  ================================
File type                         GUID                                    DLL           Verify method
================================  ======================================  ============  ================================
:ref:`MSI (.msi)`                 {000C10F1-0000-0000-C000-000000000046}  MSISIP.DLL    MsiSIPVerifyIndirectData
JScript                           {06C9E010-38CE-11D4-A2A3-00104BD35090}  wshext.dll    VerifyIndirectData
AppX                              {0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1}  AppxSip.dll   AppxSipVerifyIndirectData
AppX Bundle                       {0F5F58B3-AADE-4B9A-A434-95742D92ECEB}  AppxSip.dll   AppxBundleSipVerifyIndirectData
?                                 {18B3C141-AE0D-40F9-9465-E542AFC1ABC7}  WINTRUST.DLL  CryptSIPVerifyIndirectData
VBScript                          {1629F04E-2799-4DB5-8FE5-ACE10F17EBAB}  wshext.dll    VerifyIndirectData
Windows Script                    {1A610570-38CE-11D4-A2A3-00104BD35090}  wshext.dll    VerifyIndirectData
AppX Extensions                   {1AD2DCB4-1FC8-42EF-8D9B-1EDFB2F7C75D}  AppxSip.dll   ExtensionsSipVerifyIndirectData
AppX P7X Signature                {5598CFF1-68DB-4340-B57F-1CACF88C9A51}  AppxSip.dll   P7xSipVerifyIndirectData
PowerShell (.ps1)                 {603BCC1F-4B59-4E08-B724-D2C6297EF351}  pwrshsip.dll  PsVerifyHash
Structured Storage*               {941C2937-1292-11D1-85BE-00C04FC295EE}  WINTRUST.DLL  CryptSIPVerifyIndirectData
:ref:`CTL <Catalog (.cat)>`       {9BA61D3F-E73A-11D0-8CD2-00C04FC295EE}  WINTRUST.DLL  CryptSIPVerifyIndirectData
Electronic Software Distribution  {9F3053C5-439D-4BF7-8A77-04F0450A1D9F}  EsdSip.dll    EsdSipVerifyHash
Office VBA                        {9FA65764-C36F-4319-9737-658A34585BB7}  mso.dll       MsoVBADigSigVerifyIndirectData
:ref:`PE (.exe)`                  {C689AAB8-8E78-11D0-8C47-00C04FC295EE}  WINTRUST.DLL  CryptSIPVerifyIndirectData
Java Class*                       {C689AAB9-8E78-11D0-8C47-00C04FC295EE}  WINTRUST.DLL  CryptSIPVerifyIndirectData
Cabinet (.cab)                    {C689AABA-8E78-11D0-8C47-00C04FC295EE}  WINTRUST.DLL  CryptSIPVerifyIndirectData
Encrypted AppX                    {CF78C6DE-64A2-4799-B506-89ADFF5D16D6}  AppxSip.dll   EappxSipVerifyIndirectData
Encrypted AppX Bundle             {D1D04F0C-9ABA-430D-B0E4-D7E96ACCE66C}  AppxSip.dll   EappxBundleSipVerifyIndirectData
Flat Image                        {DE351A42-8E59-11D0-8C47-00C04FC295EE}  WINTRUST.DLL  CryptSIPVerifyIndirectData
:ref:`Catalog (.cat)`             {DE351A43-8E59-11D0-8C47-00C04FC295EE}  WINTRUST.DLL  CryptSIPVerifyIndirectData
================================  ======================================  ============  ================================

The SIPs for Structured Storage and Java Class are deprecated and may be absent in
current versions of Windows.

.. seealso::

   More information about developing, and abusing, custom SIPs can be found here:

   * `vcjones.dev blog <https://vcsjones.dev/subject-interface-packages/>`_
   * `SpecterOps - Subverting Trust in Windows <https://specterops.io/wp-content/uploads/sites/3/2022/06/SpecterOps_Subverting_Trust_in_Windows.pdf>`_
   * `Microsoft docs on mssip.h <https://learn.microsoft.com/en-us/windows/win32/api/mssip/>`_

AuthenticodeFile subclasses
===========================
In Signify, we implement a subset of available file types by subclassing
:class:`signify.authenticode.AuthenticodeFile`. Each subclass implements the
required methods for extracting the signature from the file and verifying it, much like
SIPs in Windows.

The easiest method of using this is by simply calling
:meth:`signify.authenticode.AuthenticodeFile.from_stream`, which should automatically
determine the appropriate subclass based on the provided file.

In some cases, you may need to instantiate a subclass yourself, or access various
methods provided by a subclass.

PE (.exe)
---------
This class is used for the verification of Portable Executable (PE) files. This file
type is best documented and forms the basis of our knowledge of how Authenticode works.
See the official 2008 Microsoft paper
`Windows Authenticode Portable Executable Signature Format <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx>`_
for more details on this format.

Hash calculation
################
The PE Certificate Table contains the Authenticode SignedData block for PE files. As
a result, properly hashing PE files requires omitting the 4-byte checksum in the PE
header, the certificate table pointer in the PE Data Directories, and the certificate
table itself.

Note that the paper specifies that the sections must be hashed in file size order, which
means that we can just use the file on disk for our purposes.

The SignedData object itself is located in the certificate table, which is comprised
of a simple structure::

    typedef struct _WIN_CERTIFICATE
    {
        DWORD       dwLength;
        WORD        wRevision;
        WORD        wCertificateType;
        BYTE        bCertificate[ANYSIZE_ARRAY];
    } WIN_CERTIFICATE, *LPWIN_CERTIFICATE

The ``wRevision`` must be ``0x0200`` (revision 2.0), as there's currently no support
for ``0x0100`` (revision 1.0). Similarly, the ``wCertificateType`` must be ``0x0002``
(PKCS Signed Data).

Page hashes
###########
The ``SpcIndirectDataContent`` class may contain a binary structure that defines
hashes for portions of the file (in the ``SpcLink.moniker`` field). If this is the case,
the moniker will use class ID ``a6b586d5-b4a1-2466-ae05-a217da8e60d6``, and its
serialized data will contain another ``SpcAttributeTypeAndOptionalValue`` with
*microsoft_spc_pe_image_page_hashes_v1* (OID ``1.3.6.1.4.1.311.2.3.1``) for SHA-1 or
*microsoft_spc_pe_image_page_hashes_v2* (OID ``1.3.6.1.4.1.311.2.3.2``) for SHA-256.

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

.. autoclass:: SignedPEFile
   :members:
   :special-members: __init__

.. autoclass:: SignedPEFingerprinter
   :members:
   :special-members: __init__

MSI (.msi)
----------
This class is used for the verification of MSI files.

The MSI OLE file will contain a ``DigitalSignature`` section that contains the
SignedData object.

The digest is calculated by recursively hashing all content entries in the OLE file in
alphabetical order, except for the ``DigitalSignature`` and ``MsiDigitalSignatureEx``
sections.

When the ``MsiDigitalSignatureEx`` section is present, a so-called pre-hash is also
calculated. The pre-hash hashes the metadata, i.e. various properties of (recursive)
section headers, including the root section. The calculated pre-hash is prepended
to the content hashed in ``DigitalSignature`` (i.e. ``hash(hash(metadata) + content)``)
and additionally stored in the ``MsiDigitalSignatureEx`` section.

.. autoclass:: SignedMsiFile
   :members:
   :special-members: __init__

Catalog (.cat)
--------------
Catalog Files (.cat) are used for externally signing files, mostly used in the case of
driver files. They can be used to sign virtually any type of file. They are usually
found in a subdirectory of ``C:\Windows\System32\CatRoot``.

The same file format is used by Certificate Trust Lists (e.g. authroot.stl), which is
used for distributing lists of certificates, particularly the Microsoft Root CA program,
but can be used more widely.

Both files can be checked, although the content of the file is simply signed by using
a generic SignedData object, and there's no indirect data that contains an additional
signature. That's why this file format does not return ``AuthenticodeSignedData``
objects, but rather a different subclass of ``SignedData``.

.. autoclass:: CtlFile
   :members:
   :special-members: __init__

Signed Data File (.p7x)
-----------------------
Simple transparent AuthenticodeFile class that operates on an already-parsed
:class:`signify.authenticode.AuthenticodeSignedData`. This can be used in places where
the parsed SignedData object is present, but the original file is no longer present,
or for parsing P7X files.

Note that this subclass does not know what content to hash or how to hash it, and so
has only limited use.

.. autoclass:: AuthenticodeSignedDataFile
   :members:
   :special-members: __init__
