# This is a PyInstaller `hook
# <https://pyinstaller.readthedocs.io/en/stable/hooks.html>`_.
# See the `PyInstaller manual <https://pyinstaller.readthedocs.io/>`_
# for more information.
#
import os
from pathlib import Path

datas = [(os.path.join(Path(__file__).parent, "..", "certs"), "signify/certs")]
hiddenimports = ['encodings']
