"""enclavize/aws/events.py against real CloudTrail. Read-only, so safe anywhere.

This is also the tool for tuning the whitelist: it prints the (eventSource,
eventName) pairs a real account actually produces, which is the thing the
offline tests cannot know.
"""

import datetime
from collections import Counter

import pytest

from enclavize.aws import ec2 as ec2mod
from enclavize.aws import events
from enclavize.logic import verdict

pytestmark = pytest.mark.aws

WINDOW_HOURS = 24


def window():
    end = datetime.datetime.now(datetime.timezone.utc)
    return end - datetime.timedelta(hours=WINDOW_HOURS), end


def test_the_read_only_filter_is_accepted_and_excludes_reads(cloudtrail):
    """ReadOnly is a documented lookup attribute; this proves the filter works
    rather than being silently ignored."""
    start, end = window()
    found = events.write_events(cloudtrail, region="us-east-1", start=start, end=end)
    # Every event that carries the flag must say it is a write.
    assert all(event["readOnly"] in (False, None) for event in found)


def test_events_decode_into_what_the_verdict_needs(cloudtrail):
    start, end = window()
    found = events.write_events(cloudtrail, region="us-east-1", start=start, end=end)
    if not found:
        pytest.skip("no write activity in this account in the last day")
    event = found[0]
    assert event["eventName"] and event["eventSource"]
    assert isinstance(event["eventTime"], datetime.datetime)
    assert event["region"]


def test_nothing_sensitive_survives_decoding(cloudtrail):
    """requestParameters are dropped at the source, so a value passed in as a
    secret cannot reach a public log by any later path."""
    start, end = window()
    for event in events.write_events(cloudtrail, region="us-east-1", start=start, end=end):
        assert "requestParameters" not in event
        assert "responseElements" not in event


def test_the_region_sweep_visits_every_region_but_home(session, ec2, cloudtrail):
    """Per-region history means a write in an unswept region is invisible."""
    start, end = window()
    regions = ec2mod.enabled_regions(ec2)
    visited = []

    def client_for(region):
        visited.append(region)
        return session.client("cloudtrail", region_name=region)

    events.sweep_other_regions(
        client_for, regions=regions, home_region="us-east-1", start=start, end=end
    )
    assert "us-east-1" not in visited
    assert set(visited) == set(regions) - {"us-east-1"}


def test_report_the_pairs_this_account_produces(cloudtrail):
    """Not an assertion — the input for tuning the pre-workflow allow-list.

    Run this against a freshly signed-up account to see what its sign-up
    actually emits. Only root events matter: the run's own calls are matched by
    request id, not by name.
    """
    start, end = window()
    found = events.write_events(cloudtrail, region="us-east-1", start=start, end=end)
    pairs = Counter((e["eventSource"], e["eventName"]) for e in found if e["isRoot"])

    print(f"\n{len(found)} write events in the last {WINDOW_HOURS}h")
    for (source, name), count in sorted(pairs.items()):
        trusted = source in verdict.TRUSTED_SOURCES or (source, name) in verdict.PREFLIGHT_WHITELIST
        known = "     " if trusted else "NEW  "
        print(f"  {known} {count:4d}  (\"{source}\", \"{name}\"),")
