"""EventBridge Scheduler: the timer that looks for a preparing instance's word.

The receive state machine creates the schedule itself, from inside Step
Functions, and the check machine deletes it, so nothing here creates one. What
is left is what a teardown and a survey need: to find schedules by prefix and
to remove them. Not `events.py`, which is CloudTrail.
"""

from botocore.exceptions import ClientError

NOT_FOUND = "ResourceNotFoundException"


def get_schedule(scheduler, name: str):
    """The schedule's description, or None when there is no such schedule."""
    try:
        return scheduler.get_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == NOT_FOUND:
            return None
        raise


def schedules_named(scheduler, prefix: str) -> list:
    """Names of every schedule carrying the prefix, in the default group."""
    found = []
    for page in scheduler.get_paginator("list_schedules").paginate(NamePrefix=prefix):
        found += [item["Name"] for item in page["Schedules"]]
    return found


def delete_schedule(scheduler, name: str) -> None:
    """Tolerates the schedule already being gone: the check machine deletes it
    the moment it decides to switch, so a teardown usually finds nothing here."""
    try:
        scheduler.delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != NOT_FOUND:
            raise
