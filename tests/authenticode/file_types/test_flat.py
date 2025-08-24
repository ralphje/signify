import hashlib
import io

import pytest

from signify.authenticode import AuthenticodeFile
from signify.exceptions import AuthenticodeNotSignedError, ParseError
from tests._utils import open_test_data


def test_verify_flat_file():
    with open_test_data("amdacpbtscoext.inf") as f, open_test_data("oem89.cat") as cat:
        with pytest.raises(ParseError):
            AuthenticodeFile.from_stream(f)
        flat_file = AuthenticodeFile.from_stream(f, allow_flat=True)

        # Check there are no embedded signatures
        assert len(list(flat_file.iter_embedded_signatures())) == 0
        assert len(list(flat_file.iter_signatures())) == 0

        # Sanity check the fingerprint
        assert (
            flat_file.get_fingerprint(hashlib.sha1).hex()
            == "b1e795b69b4c2a901a8bc8e8b36e988c6c05d836"
        )

        # Do not pass the verify when catalog not added
        with pytest.raises(AuthenticodeNotSignedError):
            flat_file.verify()

        # Pass verification when catalog is added
        flat_file.add_catalog(cat)
        assert len(list(flat_file.iter_signatures())) == 1
        flat_file.verify()


def test_verify_flat_file_wrong_catalog():
    with (
        open_test_data("amdacpbtscoext.inf") as f,
        open_test_data(
            "115fe8649854ad531fb7ecd1318fbee6b33c9cbd78f02ed582092a96d5eb5899.cat"
        ) as cat,
    ):
        flat_file = AuthenticodeFile.from_stream(f, allow_flat=True)
        flat_file.add_catalog(cat)
        with pytest.raises(AuthenticodeNotSignedError):
            flat_file.verify()


def test_verify_flat_file_invalid_hash():
    # Change the file to a different hash
    with open_test_data("amdacpbtscoext.inf") as f:
        data = bytearray(f.read())
        data[1024] = 3

    # Add the catalog to the flat file
    flat_file = AuthenticodeFile.from_stream(io.BytesIO(data), allow_flat=True)
    with open_test_data("oem89.cat") as cat:
        flat_file.add_catalog(cat)

    # Verify that it does not recognize it as valid signature
    assert len(list(flat_file.iter_signatures())) == 0
    assert len(list(flat_file.iter_signatures(signature_types="all+"))) == 1

    # Test that it does not validate
    with pytest.raises(AuthenticodeNotSignedError):
        flat_file.verify()

    # Force the use of all catalog files, test it still does not validate
    with pytest.raises(AuthenticodeNotSignedError):
        flat_file.verify(signature_types="all+")
