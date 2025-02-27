#!/usr/bin/env python3
# Copyright 2025 Google LLC
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
from google.cloud import ndb

import osv
import osv.logs

import logging


def compute_upstream(target_bug, bugs: dict[str, osv.Bug]):
  """Computes all upstream vulnerabilities for the given bug ID.
  The returned list contains all of the bug IDs that are upstream of the
  target bug ID, including transitive upstreams."""
  visited = set()

  target_bug_upstream = target_bug.upstream
  if not target_bug_upstream:
    return []
  to_visit = set(target_bug_upstream)
  while to_visit:
    bug_id = to_visit.pop()
    if bug_id in visited:
      continue
    visited.add(bug_id)
    upstreams = set()
    if bug_id in bugs:
      bug = bugs.get(bug_id)
      upstreams = set(bug.upstream)
    to_visit.update(upstreams - visited)

  # Returns a sorted list of bug IDs, which ensures deterministic behaviour
  # and avoids unnecessary updates.
  return sorted(visited)


def get_upstreams_of_vulnerability(target_bug_id):
  # query for the bug group and all bugs where target_bug_id exists in their upstream??
  bug_group = osv.UpstreamGroup.query(osv.UpstreamGroup.db_id == target_bug_id).get()
  if bug_group is None or bug_group.upstream_ids is None:
    return []
  # bugs_group_dict = {id="CVE", [key = "x", upstream_ids]}
  bugs_group_dict= {b_id: [] for b_id in bug_group.upstream_ids}
  # bugs_group_dict = {b_id: [ndb.Key(osv.UpstreamGroup, b_id), []] for b_id in bug_group.upstream_ids}
  bug_groups_keys = [
    ndb.Key(osv.UpstreamGroup, id) for id in bug_group.upstream_ids]
  bug_groups_upstream = ndb.get_multi(bug_groups_keys)
  if bug_groups_upstream is None:
    return None
  # bug_groups_upstream = filter(None, bug_groups_upstream)
  for bug in bug_groups_upstream:
    if bug is not None:
      bugs_group_dict[bug.db_id] = bug.upstream_ids
  # for bug in bug_groups_upstream:
  #   if bug is not None:
  #     bugs_group_dict[bug.db_id][1] = bug.upstream_ids

  #   print(bug)
  #   print("")
  # bug_groups = {bug.db_id: bug.upstream_ids for bug in bug_groups_upstream if bug is not None}
  bugs_group_dict[target_bug_id] = bug_group.upstream_ids
  upstream_hierarchy = _compute_upstream_hierarchy(bug_group, bugs_group_dict)
  return upstream_hierarchy

def _compute_upstream_hierarchy(target_bug_group:osv.UpstreamGroup, bug_groups: dict[str, list[str]]):
  """Computes all upstream vulnerabilities for the given bug ID.
  The returned list contains all of the bug IDs that are upstream of the
  target bug ID, including transitive upstreams in a map hierarchy.
  bug_group:
        { db_id: bug id
          upstream_ids: str[bug_ids]
          last_modified_date}
  """
  visited = set()
  upstream_map = {}
  to_visit = set([target_bug_group.db_id])
  while to_visit:
    bug_id = to_visit.pop()
    if bug_id in visited:
      continue
    visited.add(bug_id)
    
    upstreams = set(bug_groups.get(bug_id, []))
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
      to_visit.update(upstreams - visited)
  for k, v in upstream_map.items():
    if k is target_bug_group.db_id:
      continue
    upstream_map[target_bug_group.db_id] = upstream_map[target_bug_group.db_id] - v
  return upstream_map


def _create_group(bug_id, upstream_ids):
  """Creates a new upstream group in the datastore."""

  new_group = osv.UpstreamGroup(
    id=bug_id,
    db_id=bug_id,
    upstream_ids=upstream_ids,
    last_modified=datetime.datetime.now(),
    )
  new_group.put()


def _update_group(upstream_group, upstream_ids: list):
  """Updates the upstream group in the datastore."""
  if len(upstream_ids) == 0:
    logging.info('Deleting upstream group due to too few bugs: %s',
                 upstream_ids)
    upstream_group.key.delete()
    return

  if upstream_ids == upstream_group.upstream_ids:
    return

  upstream_group.upstream_ids = upstream_ids
  upstream_group.last_modified = datetime.datetime.now()
  upstream_group.put()


def main():
  """Updates all upstream groups in the datastore by re-computing existing
  UpstreamGroups and creating new UpstreamGroups for un-computed bugs."""

  # Query for all bugs that have upstreams.
  # Use (> '' OR < '') instead of (!= '') / (> '') to de-duplicate results
  # and avoid datastore emulator problems, see issue #2093
  bugs = osv.Bug.query(ndb.OR(osv.Bug.upstream > '', osv.Bug.upstream < ''))
  bugs = {bug.db_id: bug for bug in bugs.iter()}
  all_upstream_group = osv.UpstreamGroup.query()

  for bug_id, bug in bugs.items():
    # Check if the db key is also a db_id in all_upstream_group
    bug_group = all_upstream_group.filter(
        osv.UpstreamGroup.db_id == bug_id).get()
    # Recompute the transitive upstreams and compare with the existing group
    upstream_ids = compute_upstream(bug, bugs)
    if bug_group:
      # Update the existing UpstreamGroup
      _update_group(bug_group, upstream_ids)
    else:
      # Create a new UpstreamGroup
      _create_group(bug_id, upstream_ids)


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('upstream')
  with _ndb_client.context():
    main()
