from signify.authenticode import AuthenticodeFile
from tests._utils import open_test_data


def test_detect():
    """this tests a sample that has a v0 SignerInfo structure"""
    with open_test_data("AppxSignature.p7x") as f:
        p7xfile = AuthenticodeFile.from_stream(f)
        signed_data = next(iter(p7xfile.embedded_signatures))
        assert signed_data.signed_file == p7xfile
