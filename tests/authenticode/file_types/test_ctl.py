import hashlib
import io

import pytest

from signify.authenticode import AuthenticodeFile
from signify.authenticode.signed_file import CtlFile
from signify.exceptions import (
    AuthenticodeFingerprintNotProvidedError,
    AuthenticodeVerificationError,
)
from tests._utils import open_test_data


@pytest.mark.parametrize(
    "filename",
    [
        "oem89.cat",
        "115fe8649854ad531fb7ecd1318fbee6b33c9cbd78f02ed582092a96d5eb5899.cat",
    ],
)
def test_valid_signature(filename):
    with open_test_data(filename) as f:
        afile = AuthenticodeFile.from_stream(f)
        afile.verify()

        signed_data = list((afile.embedded_signatures))
        assert len(signed_data) == 1

        # Cannot calculate fingerprint for this file
        with pytest.raises(AuthenticodeFingerprintNotProvidedError):
            assert afile.get_fingerprint(hashlib.sha256)


def test_modified_sample_fails():
    with open_test_data("oem89.cat") as f:
        data = bytearray(f.read())
    data[1024] = 3
    afile = AuthenticodeFile.from_stream(io.BytesIO(data))
    with pytest.raises(AuthenticodeVerificationError):
        afile.verify()


def test_open_unsigned_catalog():
    with open_test_data("catfiletest.cat") as f:
        afile = CtlFile.from_stream(f)
    assert len(list(afile.ctl.subjects)) == 1
    with pytest.raises(AuthenticodeVerificationError):
        afile.verify()
