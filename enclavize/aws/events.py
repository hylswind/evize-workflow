"""Fetch CloudTrail history. The judging lives in enclavize.logic.verdict.

Event history is per-region and needs no trail. Global services (IAM, STS,
Route 53, CloudFront) record into us-east-1, but a write made in any other
region is recorded only there — so a sweep has to visit every enabled region.

Delivery lags by roughly fifteen minutes, so callers poll for the anchor event
rather than reading once.
"""

import json
import time


def _decode(raw: dict, region: str) -> dict:
    """Flatten one lookup result into what the verdict needs.

    Deliberately narrow: requestParameters and responseElements are dropped here
    rather than filtered later, so values passed in as secrets cannot reach a
    log even by accident.
    """
    detail = {}
    body = raw.get("CloudTrailEvent")
    if body:
        try:
            detail = json.loads(body)
        except (TypeError, ValueError):
            detail = {}
    identity = detail.get("userIdentity", {}) or {}
    arn = identity.get("arn") or ""
    return {
        "eventId": raw.get("EventId") or detail.get("eventID"),
        # The AWS request id, which boto3 also reports back to the caller as
        # ResponseMetadata.RequestId. It is what lets the audit tell its own
        # calls apart from anybody else's rather than guessing from names.
        "requestID": detail.get("requestID"),
        "eventName": raw.get("EventName") or detail.get("eventName"),
        "eventSource": raw.get("EventSource") or detail.get("eventSource"),
        "eventTime": raw.get("EventTime"),
        "region": detail.get("awsRegion") or region,
        "principal": arn or identity.get("userName") or identity.get("type") or "?",
        # Whether root did this decides where the audit window closes, so it is
        # read two ways rather than trusting one field: CloudTrail reports the
        # root user as type "Root", and its ARN ends in ":root".
        "isRoot": identity.get("type") == "Root" or arn.endswith(":root"),
        "readOnly": detail.get("readOnly"),
    }


def write_events(ct, *, region: str, start, end) -> list:
    """Every non-read-only event in [start, end] for this region.

    ReadOnly is a supported lookup attribute, so the filtering happens server
    side; its value is the string "false".
    """
    paginator = ct.get_paginator("lookup_events")
    pages = paginator.paginate(
        StartTime=start,
        EndTime=end,
        LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
    )
    return [_decode(raw, region) for page in pages for raw in page.get("Events", [])]


def await_event(
    ct,
    *,
    region: str,
    start,
    end,
    event_name: str,
    poll_max: int,
    interval: int,
    sleep=time.sleep,
    now=time.monotonic,
) -> list:
    """Poll until `event_name` shows up, then return the whole window.

    `end` is fixed by the caller and never recomputed, so the window cannot
    drift wider while waiting for delivery to catch up.
    """
    deadline = now() + poll_max
    while True:
        events = write_events(ct, region=region, start=start, end=end)
        if any(event["eventName"] == event_name for event in events):
            return events
        if now() >= deadline:
            return events
        sleep(interval)


def sweep_other_regions(client_for_region, *, regions, home_region: str, start, end) -> list:
    """Non-read-only events from every region except the home one.

    `client_for_region` builds a CloudTrail client for a region name; injecting
    it keeps this function testable without constructing sessions.
    """
    found = []
    for region in regions:
        if region == home_region:
            continue
        found.extend(write_events(client_for_region(region), region=region, start=start, end=end))
    return found
