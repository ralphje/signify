import hashlib

import pytest

from signify.authenticode import AuthenticodeFile
from signify.exceptions import AuthenticodeFingerprintNotProvidedError
from tests._utils import open_test_data


def test_detect():
    with open_test_data("AppxSignature.p7x") as f:
        p7xfile = AuthenticodeFile.from_stream(f)
        signed_data = next(iter(p7xfile.embedded_signatures))
        assert signed_data.signed_file == p7xfile

        # Cannot calculate fingerprint for this file
        with pytest.raises(AuthenticodeFingerprintNotProvidedError):
            assert p7xfile.get_fingerprint(hashlib.sha256)
