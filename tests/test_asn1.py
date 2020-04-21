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

import datetime
from pyasn1.type import useful, univ
from pyasn1_modules.rfc5652 import Time

from signify.asn1 import guarded_ber_decode
from signify.asn1.helpers import time_to_python
from signify.authenticode import CERTIFICATE_LOCATION
from signify.certificates import Certificate
from signify.exceptions import ParseError


class TimeTest(unittest.TestCase):
    def test_conversion_utc(self):
        utctime = useful.UTCTime('120614235959Z')
        t = Time()
        t['utcTime'] = utctime
        self.assertEqual(time_to_python(t), datetime.datetime(2012, 6, 14, 23, 59, 59, tzinfo=datetime.timezone.utc))

    def test_conversion_gen(self):
        gen_time = useful.GeneralizedTime('20120614235959Z')
        t = Time()
        t['generalTime'] = gen_time
        self.assertEqual(time_to_python(t), datetime.datetime(2012, 6, 14, 23, 59, 59, tzinfo=datetime.timezone.utc))


class RDNSequenceTest(unittest.TestCase):
    def test_to_string(self):
        with open(str(CERTIFICATE_LOCATION / "Microsoft Root Certificate Authority 2010.pem"), "rb") as f:
            certificate = Certificate.from_pem(f.read())

        self.assertEqual(certificate.issuer.dn,
                         "CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, "
                         "L=Redmond, ST=Washington, C=US")

    def test_to_string_with_commas(self):
        with open(str(CERTIFICATE_LOCATION / "Verisign Time Stamping Service Root.pem"), "rb") as f:
            certificate = Certificate.from_pem(f.read())

        self.assertEqual(certificate.issuer.dn,
                         r"OU=NO LIABILITY ACCEPTED\, (c)97 VeriSign\, Inc., OU=VeriSign Time Stamping Service Root, "
                         r"OU=VeriSign\, Inc., O=VeriSign Trust Network")

    def test_get_components(self):
        with open(str(CERTIFICATE_LOCATION / "Verisign Time Stamping Service Root.pem"), "rb") as f:
            certificate = Certificate.from_pem(f.read())

        result = list(certificate.issuer.get_components("OU"))
        self.assertEqual(result, ["NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc.",
                                  "VeriSign Time Stamping Service Root",
                                  "VeriSign, Inc."])
        self.assertEqual(list(certificate.issuer.get_components("CN")), [])

    def test_get_components_none(self):
        with open(str(CERTIFICATE_LOCATION / "Verisign Time Stamping Service Root.pem"), "rb") as f:
            certificate = Certificate.from_pem(f.read())

        result = certificate.issuer.rdns
        self.assertEqual(result, [('OU', 'NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc.'),
                                  ('OU', 'VeriSign Time Stamping Service Root'),
                                  ('OU', 'VeriSign, Inc.'),
                                  ('O', 'VeriSign Trust Network')])


class GuardedBerDecodeTest(unittest.TestCase):
    def test_normal_read(self):
        self.assertTrue(guarded_ber_decode(univ.Any("\x01\x01\xff")))  # true
        self.assertFalse(guarded_ber_decode(univ.Any("\x01\x01\x00")))  # false
        self.assertIsInstance(guarded_ber_decode(univ.Any("\x05\x00")), univ.Null)  # null

    def test_extra_read(self):
        self.assertRaises(ParseError, guarded_ber_decode, univ.Any("\x05\x00\x01"))

    def test_read_error(self):
        self.assertRaises(ParseError, guarded_ber_decode, univ.Any("\x05"))
