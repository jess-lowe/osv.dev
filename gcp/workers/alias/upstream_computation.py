#!/usr/bin/env python3
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
"""OSV Upstream relation computation."""
import datetime
import logging

from google.cloud import ndb

import osv
import osv.logs

def _compute_upstream(target_bug_id, bugs):
  """Computes all upstream vulnerabilities for the given bug ID.
  The returned list contains all of the bug IDs that are upstream of the
  target bug ID, including transitive upstreams."""
  visited = set()
  target_bug_upstream = bugs[target_bug_id]
  if not target_bug_upstream:
     return []
  to_visit = set(target_bug_upstream)
  bug_ids = []
  while to_visit:
    bug_id = to_visit.pop()
    if bug_id in visited:
      continue
    visited.add(bug_id)
    bug_ids.append(bug_id)
    upstreams = set(bugs[bug_id])
    to_visit.update(upstreams-visited)
    
  # Returns a sorted list of bug IDs, which ensures deterministic behaviour
  # and avoids unnecessary updates.
  return sorted(bug_ids)

def _compute_upstream_hierarchy(target_bug_id, bugs):
    """Computes all upstream vulnerabilities for the given bug ID.
    The returned list contains all of the bug IDs that are upstream of the
    target bug ID, including transitive upstreams in a map hierarchy."""
    visited = set()
    upstream_map = {}
    to_visit = set([target_bug_id])
    while to_visit:
        bug_id = to_visit.pop()
        if bug_id in visited:
            continue
        visited.add(bug_id)
        upstreams = set(bugs[bug_id])
        if not upstreams:
            continue
        for upstream in upstreams:

            if upstream not in visited and upstream not in to_visit:
                to_visit.add(upstream)
            else:
              if bug_id not in upstream_map:
                upstream_map[bug_id] = set([upstream])
              else:
                upstream_map[bug_id].add(upstream)
        upstream_map[bug_id] = upstreams
        to_visit.update(upstreams-visited)
    for k, v in upstream_map.items():
      if k is target_bug_id:
        continue
      upstream_map[target_bug_id] = upstream_map[target_bug_id]-v
    return upstream_map

def main():
  bugs_query = osv.Bug.query(ndb.OR(osv.Bug.upstream > '', osv.Bug.upstream < ''))
  bugs = {}
  for bug in bugs_query:
    bugs[bug.db_id] = bug.upstream
  # bug_ids = _compute_upstream_hierarchy('CVE-3', bugs)
  # logging.info(bug_ids)

if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('upstream')
  with _ndb_client.context():
    main()
