import hashlib

import pytest

from signify.authenticode import AuthenticodeFile
from signify.exceptions import AuthenticodeFingerprintNotProvidedError
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
