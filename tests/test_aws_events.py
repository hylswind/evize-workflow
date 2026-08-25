"""Fetching history: the ReadOnly filter, the frozen window, and the region sweep.

moto has no lookup_events paginator worth driving, so the client is faked; what
matters here is the request shape and the decoding, both of which are pinned
against the real service by tests/aws/test_events.py.
"""

from datetime import datetime, timedelta, timezone

import json
import pytest
from constants import clock, no_sleep

from enclavize.aws import events as ev

T0 = datetime(2026, 8, 24, 3, 0, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(hours=1)


def raw(name, *, source="iam.amazonaws.com", offset=0, region="us-east-1", **detail):
    body = {
        "eventName": name,
        "eventSource": source,
        "awsRegion": region,
        "readOnly": False,
        "userIdentity": {"arn": "arn:aws:iam::1:root", "type": "Root"},
        **detail,
    }
    return {
        "EventId": f"id-{name}",
        "EventName": name,
        "EventSource": source,
        "EventTime": T0 + timedelta(seconds=offset),
        "CloudTrailEvent": json.dumps(body),
    }


class FakeTrail:
    """Records how it was queried and replays canned pages."""

    def __init__(self, pages, region="us-east-1"):
        self.pages = pages
        self.region = region
        self.requests = []

    def get_paginator(self, name):
        assert name == "lookup_events"
        return self

    def paginate(self, **kwargs):
        self.requests.append(kwargs)
        return list(self.pages)


def test_only_non_read_only_events_are_requested():
    trail = FakeTrail([{"Events": []}])
    ev.write_events(trail, region="us-east-1", start=T0, end=T1)
    attrs = trail.requests[0]["LookupAttributes"]
    # ReadOnly is a supported lookup attribute, so this filters server side.
    assert attrs == [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}]


def test_the_requested_window_is_exactly_what_was_asked_for():
    trail = FakeTrail([{"Events": []}])
    ev.write_events(trail, region="us-east-1", start=T0, end=T1)
    assert trail.requests[0]["StartTime"] == T0
    assert trail.requests[0]["EndTime"] == T1


def test_events_are_flattened_for_judging():
    trail = FakeTrail([{"Events": [raw("CreateRole")]}])
    event = ev.write_events(trail, region="us-east-1", start=T0, end=T1)[0]
    assert event["eventName"] == "CreateRole"
    assert event["eventSource"] == "iam.amazonaws.com"
    assert event["region"] == "us-east-1"
    assert event["principal"] == "arn:aws:iam::1:root"
    assert event["eventTime"] == T0


def test_request_parameters_never_survive_decoding():
    """Dropped at the source so a secret cannot reach a log by any later path."""
    trail = FakeTrail(
        [{"Events": [raw("CreateUser", requestParameters={"password": "hunter2"},
                          responseElements={"secretAccessKey": "AKIAsecret"})]}]
    )
    event = ev.write_events(trail, region="us-east-1", start=T0, end=T1)[0]
    assert "hunter2" not in str(event)
    assert "AKIAsecret" not in str(event)
    assert "requestParameters" not in event


def test_pages_are_all_consumed():
    trail = FakeTrail([{"Events": [raw("A")]}, {"Events": [raw("B")]}])
    names = [e["eventName"] for e in ev.write_events(trail, region="us-east-1", start=T0, end=T1)]
    assert names == ["A", "B"]


def test_a_malformed_event_body_still_yields_the_envelope():
    broken = {"EventId": "x", "EventName": "CreateRole", "EventSource": "iam.amazonaws.com",
              "EventTime": T0, "CloudTrailEvent": "not json"}
    event = ev.write_events(FakeTrail([{"Events": [broken]}]), region="us-east-1", start=T0, end=T1)[0]
    assert event["eventName"] == "CreateRole"
    assert event["region"] == "us-east-1"


def test_await_returns_as_soon_as_the_anchor_arrives():
    trail = FakeTrail([{"Events": [raw("CreateAccount", source="signin.amazonaws.com")]}])
    found = ev.await_event(
        trail, region="us-east-1", start=T0, end=T1, event_name="CreateAccount",
        poll_max=1200, interval=30, sleep=no_sleep, now=clock([0, 1]),
    )
    assert [e["eventName"] for e in found] == ["CreateAccount"]
    assert len(trail.requests) == 1


def test_await_keeps_polling_while_delivery_lags():
    class Lagging(FakeTrail):
        def paginate(self, **kwargs):
            self.requests.append(kwargs)
            if len(self.requests) < 3:
                return [{"Events": []}]
            return [{"Events": [raw("CreateAccount", source="signin.amazonaws.com")]}]

    trail = Lagging([])
    ev.await_event(
        trail, region="us-east-1", start=T0, end=T1, event_name="CreateAccount",
        poll_max=1200, interval=30, sleep=no_sleep, now=clock([0, 1, 2, 3]),
    )
    assert len(trail.requests) == 3


def test_the_window_end_never_drifts_while_polling():
    """A widening window would keep sweeping in activity that arrived later."""

    class Empty(FakeTrail):
        def paginate(self, **kwargs):
            self.requests.append(kwargs)
            return [{"Events": []}]

    trail = Empty([])
    # Polls twice, then the clock passes the deadline so the loop ends.
    ev.await_event(
        trail, region="us-east-1", start=T0, end=T1, event_name="CreateAccount",
        poll_max=1200, interval=30, sleep=no_sleep, now=clock([0, 1, 2, 5000]),
    )
    assert len(trail.requests) > 1
    assert {r["EndTime"] for r in trail.requests} == {T1}


def test_await_gives_up_and_returns_what_it_saw():
    trail = FakeTrail([{"Events": [raw("CreateRole")]}])
    found = ev.await_event(
        trail, region="us-east-1", start=T0, end=T1, event_name="CreateAccount",
        poll_max=1200, interval=30, sleep=no_sleep, now=clock([0, 5000]),
    )
    assert [e["eventName"] for e in found] == ["CreateRole"]


def test_the_sweep_skips_the_home_region():
    # Home is read separately with the anchor poll; re-reading it would double
    # every event and make the whitelist look violated.
    built = []

    def client_for(region):
        built.append(region)
        return FakeTrail([{"Events": [raw("RunInstances", source="ec2.amazonaws.com", region=region)]}], region)

    found = ev.sweep_other_regions(
        client_for, regions=["us-east-1", "us-west-2", "eu-west-1"],
        home_region="us-east-1", start=T0, end=T1,
    )
    assert built == ["us-west-2", "eu-west-1"]
    assert {e["region"] for e in found} == {"us-west-2", "eu-west-1"}


def test_the_sweep_reports_nothing_for_untouched_regions():
    found = ev.sweep_other_regions(
        lambda region: FakeTrail([{"Events": []}], region),
        regions=["us-east-1", "us-west-2"], home_region="us-east-1", start=T0, end=T1,
    )
    assert found == []
