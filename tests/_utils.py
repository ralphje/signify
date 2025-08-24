import pathlib

root_dir = pathlib.Path(__file__).parent


def data_path(filename: str) -> pathlib.Path:
    return root_dir / "test_data" / filename


def open_test_data(filename: str, mode: str = "rb"):
    return data_path(filename).open(mode)
