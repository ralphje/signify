#!/usr/bin/python

# Copyright 2011 Google Inc. All Rights Reserved.
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
#
# Author: caronni@google.com (Germano Caronni)

"""Wrapper to exercise authenticode signature validation.

   Uses test data from the fingerprinter to actually parse out a
   signature blob, and invoke the validation routines.
"""

# I really want to use parens in print statements.
# pylint: disable-msg=C6003

import os
import pickle
import time

import auth_data
import pecoff_blob


# EVIL EVIL -- Monkeypatch to extend accessor
# This is necessary for pyasn1 < 0.13b
def F(self, idx):
  if type(idx) is int:
    return self.getComponentByPosition(idx)
  else: return self.getComponentByName(idx)
from pyasn1.type import univ  # pylint: disable-msg=C6204
univ.SequenceAndSetBase.__getitem__ = F
del F, univ
# EVIL EVIL


def main():
  data_file = os.path.join('.', 'test_data', 'pciide.sys.res')

  with file(data_file, 'rb') as resf:
    exp_results = pickle.load(resf)

  signed_pecoffs = [x for x in exp_results if x['name'] == 'pecoff' and
                    'SignedData' in x]
  # If the invoker of the fingerprinter specified multiple fingers for pecoff
  # hashing (possible, even if not sensible), then there can be more than one
  # entry in this list.
  signed_pecoff = signed_pecoffs[0]

  signed_datas = signed_pecoff['SignedData']
  # There may be multiple of these, if the windows binary was signed multiple
  # times, e.g. by different entities. Each of them adds a complete SignedData
  # blob to the binary.
  signed_data = signed_datas[0]

  blob = pecoff_blob.PecoffBlob(signed_data)

  auth = auth_data.AuthData(blob.getCertificateBlob())
  content_hasher_name = auth.digest_algorithm().name
  computed_content_hash = signed_pecoff[content_hasher_name]

  auth.ValidateAsn1()
  auth.ValidateHashes(computed_content_hash)
  auth.ValidateSignatures()
  auth.ValidateCertChains(time.gmtime())

  print('Program: %s, URL: %s' % (auth.program_name, auth.program_url))
  print('countersig: %d' % auth.has_countersignature)
  print('Timestamp: %s' % auth.counter_timestamp)


if __name__ == '__main__':
  main()
