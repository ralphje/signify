# This is a derivative, modified, work from the verify-sigs project.
# Please refer to the LICENSE file in the distribution for more
# information. Original filename: asn1/time_test.py
#
# Parts of this file are licensed as follows:
#
# Copyright 2012 Google Inc. All Rights Reserved.
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

import unittest

from signify.authenticode import TRUSTED_CERTIFICATE_STORE


class RDNSequenceTest(unittest.TestCase):
    def test_to_string(self):
        certificate = TRUSTED_CERTIFICATE_STORE.find_certificate(
            sha256_fingerprint=(
                "DF545BF919A2439C36983B54CDFC903DFA4F37D3996D8D84B4C31EEC6F3C163E"
            )
        )

        self.assertEqual(
            certificate.issuer.dn,
            "CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, "
            "L=Redmond, ST=Washington, C=US",
        )

    def test_to_string_with_commas(self):
        certificate = TRUSTED_CERTIFICATE_STORE.find_certificate(
            sha256_fingerprint=(
                "5B789987F3C4055B8700941B33783A5F16E0CFF937EA32011FE04779F7635308"
            )
        )

        self.assertEqual(
            certificate.issuer.dn,
            r"OU=NO LIABILITY ACCEPTED\, (c)97 VeriSign\, Inc., OU=VeriSign Time"
            r" Stamping Service Root, "
            r"OU=VeriSign\, Inc., O=VeriSign Trust Network",
        )

    def test_get_components(self):
        certificate = TRUSTED_CERTIFICATE_STORE.find_certificate(
            sha256_fingerprint=(
                "5B789987F3C4055B8700941B33783A5F16E0CFF937EA32011FE04779F7635308"
            )
        )

        result = list(certificate.issuer.get_components("OU"))
        self.assertEqual(
            result,
            [
                "NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc.",
                "VeriSign Time Stamping Service Root",
                "VeriSign, Inc.",
            ],
        )
        self.assertEqual(list(certificate.issuer.get_components("CN")), [])

    def test_get_components_none(self):
        certificate = TRUSTED_CERTIFICATE_STORE.find_certificate(
            sha256_fingerprint=(
                "5B789987F3C4055B8700941B33783A5F16E0CFF937EA32011FE04779F7635308"
            )
        )

        result = certificate.issuer.rdns
        self.assertEqual(
            result,
            (
                ("OU", "NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc."),
                ("OU", "VeriSign Time Stamping Service Root"),
                ("OU", "VeriSign, Inc."),
                ("O", "VeriSign Trust Network"),
            ),
        )
