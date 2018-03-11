pesigcheck
==========
**This module is not done, and contains a mix of updated and outdated code.**

pesigcheck is a Python module to compute and validate hashes on different file
types, mostly aimed at computing PE Authenticode-signed binaries.

This module is a forked from Google's ``verify_sigs`` module, updated to fit
modern Python standards and be compatible with Python 3. It is **not** a drop-in
replacement, as significant changes have occurred.

This module is not made for compatibility with Python 2.x

Fingerprinter
-------------
The fingerprinter is a simple module that allows you to apply multiple
hashes in a single run. It is intended to be used as follows:

```python 
>>> with open("file", "rb") as f:
...     fingerprinter = Fingerprinter(file_obj)
...     fingerprinter.add_hashers(hashlib.sha1, hashlib.sha256)
...     print(fingerprinter.hash())

{"sha1": ..., "sha256": ...}

```

However, you can also use it to calculate Authenticode hashes as follows:
```python 
>>> with open("file", "rb") as f:
...     fingerprinter = AuthenticodeFingerprinter(file_obj)
...     fingerprinter.add_authenticode_hashers(hashlib.sha1, hashlib.sha256)
...     print(fingerprinter.hash())

{"sha1": ..., "sha256": ...}

```
You can also combine these for more efficiency:
```python 
>>> with open("file", "rb") as f:
...     fingerprinter = AuthenticodeFingerprinter(file_obj)
...     fingerprinter.add__hashers(hashlib.sha1, hashlib.sha256)
...     fingerprinter.add_authenticode_hashers(hashlib.sha1, hashlib.sha256)
...     print(fingerprinter.hashes())

{"generic": {"sha1": ..., "sha256": ...}, 
 "authentihash": {"sha1": ..., "sha256": ...}}

```

Files not yet converted
-----------------------
auth_data.py
Basic container for authenticode data, as represented in ASN.1 together
with accessor and validator functions. Currently provides limited validation,
in particular certificate chain validation is missing.

auth_data_test.py
Set of tests on auth_data, assuring that pregenerated data still
produces the same reuslts.

pecoff_blob.py
Container for PECOFF format part of authenticode blobs, as provided
by the fingerprinter library in the SignedData structure.

print_pe_certs.py
Exercises authenticode validation routines, prints out hashes and certs.




THANKS
------
Many thanks to Darren and Michael for motivating me to work through tangled
standards.
Many thanks to Ero for pefile, and to Ilya Etingof for pyasn1, very useful
examples code for x509 and pkcs7 parsing, and finally for extending the 
parser to handle 'any' type!

Germano Caronni, 2012/4/26
caronni@google.com , gec@acm.org
