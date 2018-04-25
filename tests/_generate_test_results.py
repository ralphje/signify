# This is a derivative, modified, work from the verify-sigs project.
# Please refer to the LICENSE file in the distribution for more
# information. Original filename: fingerprinter_test.py
#
# Parts of this file are licensed as follows:
#
# Copyright 2010 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import hashlib
import json
import pathlib

from signify.fingerprinter import AuthenticodeFingerprinter


def main():
    for filename in pathlib.Path("tests/test_data").iterdir():
        if str(filename).endswith(".res"):
            continue
        print("Updating {}...".format(filename))
        with open(str(filename), "rb") as file_obj:
            fingerprinter = AuthenticodeFingerprinter(file_obj)
            fingerprinter.add_hashers(hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512)
            fingerprinter.add_authenticode_hashers(hashlib.md5, hashlib.sha1, hashlib.sha256)
            results = fingerprinter.hashes()

        # convert to hex
        for v in results.values():
            for k, b in v.items():
                v[k] = b.hex()
        with open(str(filename) + ".res", "w") as res_obj:
            json.dump(results, res_obj)


if __name__ == '__main__':
    main()
