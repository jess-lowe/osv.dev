# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Alias computation tests."""
import datetime
import os
import unittest
import logging 
from google.cloud import ndb
from google.protobuf import timestamp_pb2

import osv
import upstream_computation
from osv import tests

TEST_DATA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'testdata')


class UpstreamTest(unittest.TestCase, tests.ExpectationTest(TEST_DATA_DIR)):
  """Upstream tests."""
  def setUp(self):
    self.maxDiff = None
    tests.reset_emulator()
    osv.Bug(
        id='CVE-1',
        db_id='CVE-1',
        status=1,
        upstream = [],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='CVE-2',
        db_id='CVE-2',
        status=1,
        upstream = ['CVE-1'],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='CVE-3',
        db_id='CVE-3',
        status=1,
        upstream = ['CVE-1', 'CVE-2'],
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()

  def test_compute_upstream(self):
    """Tests basic case."""
    
    bugs_query = osv.Bug.query(ndb.OR(osv.Bug.upstream > '', osv.Bug.upstream < ''))
    
    bugs = {}
    for bug in bugs_query:
      print(bug.db_id)
      print(bug.upstream)
      bugs[bug.db_id] = bug.upstream
    # print(bugs)
    bug_ids = upstream_computation._compute_upstream_hierarchy('CVE-3', bugs)

    # bug_ids = osv.AliasGroup.query(
        # osv.AliasGroup.bug_ids == 'aaa-123').get().bug_ids
    self.assertEqual(['CVE-1','CVE-2'], bug_ids)


if __name__ == '__main__':
  ds_emulator = tests.start_datastore_emulator()
  try:
    with ndb.Client().context() as context:
      context.set_memcache_policy(False)
      context.set_cache_policy(False)
      # logging.basicConfig( stream=sys.stderr )
      logging.getLogger( "UpstreamTest.test_compute_upstream" ).setLevel( logging.DEBUG )
      unittest.main()
  finally:
    tests.stop_emulator()
