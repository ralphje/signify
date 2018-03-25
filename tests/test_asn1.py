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
from pyasn1.type import useful

from signify.asn1.x509_time import Time


class TimeTest(unittest.TestCase):
    def test_conversion_utc(self):
        utctime = useful.UTCTime('120614235959Z')
        t = Time()
        t['utcTime'] = utctime
        self.assertEqual(t.to_python_time(), datetime.datetime(2012, 6, 14, 23, 59, 59, tzinfo=datetime.timezone.utc))

    def test_conversion_gen(self):
        gen_time = useful.GeneralizedTime('20120614235959Z')
        t = Time()
        t['generalTime'] = gen_time
        self.assertEqual(t.to_python_time(), datetime.datetime(2012, 6, 14, 23, 59, 59, tzinfo=datetime.timezone.utc))

