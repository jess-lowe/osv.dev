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
from google.cloud import ndb
from collections import OrderedDict
import osv
import osv.logs

import logging


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
    to_visit.update(upstreams - visited)

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
      to_visit.update(upstreams - visited)
  for k, v in upstream_map.items():
    if k is target_bug_id:
      continue
    upstream_map[target_bug_id] = upstream_map[target_bug_id] - v
  return upstream_map


def _get_downstreams_of_bug_query(bug_id):
  """Returns a list of all downstream bugs of the given bug ID."""
  downstreams = {}
  for bug in osv.Bug.query(osv.Bug.upstream == bug_id):
    downstreams[bug.db_id] = bug.upstream
  return downstreams


def _get_downstreams_of_bug(bug_id, bugs):
  """Returns a list of all downstream bugs of the given bug ID."""
  downstreams = []
  for bug in bugs:
    if bug_id in bugs[bug]:
      downstreams.append(bug)
  return downstreams


def compute_downstream_hierarchy(target_bug_id: str) -> dict[str, set[str]]:
  """Computes all downstream vulnerabilities for the given bug ID.

  Returns a dictionary representing the downstream hierarchy.  Keys are bug IDs,
  and values are sets of their immediate downstream bug IDs. The root bug ID's
  value will be the set of all leaf nodes in its downstream hierarchy.

  Args:
    target_bug_id: The ID of the bug to compute the downstream hierarchy for.

  Returns:
    A dictionary representing the downstream hierarchy.
  """

  downstream_map: dict[str, set[str]] = {}
  all_downstreams = _get_downstreams_of_bug_query(target_bug_id)
  # Sort downstreams by number of upstreams
  all_downstreams = OrderedDict(
    sorted(all_downstreams.items(), key=lambda item:len(item[1])))

  leaf_bugs: set[str] = set()

  for bug_id, _ in all_downstreams.items():
    immediate_downstreams = _get_downstreams_of_bug(bug_id, all_downstreams)
    if not immediate_downstreams:
      leaf_bugs.add(bug_id)
    else:
      downstream_map[bug_id] = set(immediate_downstreams)

  root_leaves = leaf_bugs.copy()
  for bug_id, downstream_bugs in downstream_map.items():
    for leaf in leaf_bugs:
      if leaf in downstream_bugs:
        root_leaves.discard(leaf)
    root_leaves.add(bug_id)

  downstream_map[target_bug_id] = root_leaves
  return downstream_map

def compute_downstream_hierarchy_2(target_bug_id: str) -> dict[str, set[str]]:
  """Computes all downstream vulnerabilities for the given bug ID.

  Returns a dictionary representing the downstream hierarchy.  Keys are bug IDs,
  and values are sets of their immediate downstream bug IDs. The root bug ID's
  value will be the set of all leaf nodes in its downstream hierarchy.

  Args:
    target_bug_id: The ID of the bug to compute the downstream hierarchy for.

  Returns:
    A dictionary representing the downstream hierarchy.
  """

  downstream_map: dict[str, set[str]] = {}
  all_downstreams = _get_downstreams_of_bug_query(target_bug_id)
  # Sort downstreams by number of upstreams
  all_downstreams = OrderedDict(
    sorted(all_downstreams.items(), key=lambda item:-len(item[1])))

  leaf_bugs: set[str] = set()
  visited: set[str] = set()

  for bug_id, _ in all_downstreams.items():
    if bug_id in visited:
      continue
    immediate_downstreams = _get_downstreams_of_bug(bug_id, all_downstreams)
    

  root_leaves = leaf_bugs.copy()
  for bug_id, downstream_bugs in downstream_map.items():
    for leaf in leaf_bugs:
      if leaf in downstream_bugs:
        root_leaves.discard(leaf)
    root_leaves.add(bug_id)

  downstream_map[target_bug_id] = root_leaves
  return downstream_map

def _create_group(bug_id, upstream_ids):
  """Creates a new upstream group in the datastore."""

  new_group = osv.UpstreamGroup(db_id=bug_id)
  new_group.upstream_ids = upstream_ids
  new_group.last_modified = datetime.datetime.now()
  new_group.put()


def _update_group(upstream_group, upstream_ids: list):
  """Updates the alias group in the datastore."""
  if len(upstream_ids) < 1:
    logging.info('Deleting alias group due to too few bugs: %s', upstream_ids)
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

  all_upstream_group = osv.UpstreamGroup.query()

  # for every bug, check if it has an UpstreamGroup.
  for bug in bugs:
    # check if the db key is also a db_id in all_upstream_group
    b = all_upstream_group.filter(osv.UpstreamGroup.db_id == bug.db_id)
    if b:
      #recompute the transitive upstreams and compare with the existing group
      upstream_ids = _compute_upstream(bug.db_id, all_upstream_group)
      _update_group(b, upstream_ids)
    else:
      # Create a new UpstreamGroup
      upstream_ids = _compute_upstream(bug.db_id, all_upstream_group)
      _create_group(bug, upstream_ids)


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('upstream')
  with _ndb_client.context():
    main()
