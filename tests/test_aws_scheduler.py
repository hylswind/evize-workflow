"""EventBridge Scheduler: finding and removing what the receive machine made."""

import boto3
import pytest
from constants import REGION
from moto import mock_aws

from enclavize.aws import scheduler as schedmod


@pytest.fixture
def scheduler():
    with mock_aws():
        yield boto3.client("scheduler", region_name=REGION)


def one_time(scheduler, name):
    scheduler.create_schedule(
        Name=name,
        ScheduleExpression="at(2030-01-01T00:00:00)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": "arn:aws:states:us-east-1:123456789012:stateMachine:sw",
                "RoleArn": "arn:aws:iam::123456789012:role/r"},
    )


def test_a_missing_schedule_is_none_rather_than_an_error(scheduler):
    # Its absence is the ordinary case: a one-time schedule deletes itself.
    assert schedmod.get_schedule(scheduler, "enclavize-apply-switch") is None


def test_a_present_schedule_is_described(scheduler):
    one_time(scheduler, "enclavize-apply-switch")
    found = schedmod.get_schedule(scheduler, "enclavize-apply-switch")
    assert found["Name"] == "enclavize-apply-switch"
    assert found["ScheduleExpression"] == "at(2030-01-01T00:00:00)"


def test_schedules_are_found_by_prefix(scheduler):
    one_time(scheduler, "t1234-apply-switch")
    one_time(scheduler, "someone-elses")
    assert schedmod.schedules_named(scheduler, "t1234-") == ["t1234-apply-switch"]


def test_deleting_tolerates_the_schedule_having_fired_already(scheduler):
    one_time(scheduler, "enclavize-apply-switch")
    schedmod.delete_schedule(scheduler, "enclavize-apply-switch")
    schedmod.delete_schedule(scheduler, "enclavize-apply-switch")
    assert schedmod.get_schedule(scheduler, "enclavize-apply-switch") is None
