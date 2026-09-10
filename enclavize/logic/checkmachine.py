"""The checking state machine's definition, as data.

Started by the timer the receive machine set, every few minutes, with no
input. Everything it needs is in Parameter Store: `pending` says which commit
is waiting and what is serving; `ready` is the preparing instance's word that
the switch may go ahead. Each run reads both and does one of three things —
nothing, because there is no word yet; clears a word that is not for this
commit; or switches. A switch is a few seconds' work: launch the new commit,
write it down as serving, and tidy.

The guarantee is that a commit is launched once, however many runs overlap.
The first thing a switching run does is delete the timer, and a delete is
atomic: of two runs that both decided to switch, one gets NotFound and stops.
That delete is the lock, and it is also the first side effect — nothing before
it changes anything.

Ready has to name the commit that is pending, not merely exist. A preparer
that says ready late — after its apply was superseded — names the commit *it*
was told about, which is not the one waiting now, so it is cleared rather than
counted. Otherwise a stale word could launch a later commit before its own
preparer had spoken.

The wait is bounded. A preparer that never says ready is given the timeout,
and then the switch goes ahead regardless; the preparer, if it is still
running, is stopped first. Waiting is a courtesy to the serving version, not
a veto.

Standard rather than Express: each run is short, but its history is the only
record of a switch having happened, and Express keeps none.
"""

from . import naming
from .statemachine import (
    NEW,
    NO_SCHEDULE,
    NOT_FOUND,
    PARAMETER_RETRY,
    run_instances,
    user_data_expression,
)


def _tidy(next_state: str) -> list:
    """After the switch: a failure is noted and the next thing is tried."""
    return [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.tidyError", "Next": next_state}]


def _decision(timeout_seconds: int) -> dict:
    """Ready for this commit, or out of time: go. Ready for another: clear it.
    Neither: wait for the next look.

    JSONata, because JSONPath's Choice can compare a field with a literal but
    not two fields with each other, and cannot add to a timestamp at all.
    """
    ready = "$states.input.ready.Parameter.Value"
    pending = "$states.input.pending"
    return {
        "Type": "Choice",
        "QueryLanguage": "JSONata",
        "Choices": [
            {
                "Condition": f"{{% $exists({ready}) and {ready} = {pending}.commit %}}",
                "Next": "ClaimIt",
            },
            {
                "Condition": (
                    f"{{% $toMillis({pending}.at) + {timeout_seconds * 1000} "
                    "<= $toMillis($now()) %}"
                ),
                "Next": "ClaimIt",
            },
            {"Condition": f"{{% $exists({ready}) %}}", "Next": "ClearStaleReady"},
        ],
        "Default": "NotYet",
    }


def build_definition(
    *,
    app_repo: str,
    domain: str,
    image_id: str,
    instance_type: str,
    subnet_id: str,
    instance_profile: str,
    name_tag: str,
    dashboard_bucket: str,
    schedule_name: str,
    current_param: str,
    pending_param: str,
    ready_param: str,
    timeout_seconds: int,
) -> dict:
    """A Standard definition that looks, and switches when it is time."""
    launch = dict(image_id=image_id, instance_type=instance_type, subnet_id=subnet_id,
                  instance_profile=instance_profile, name_tag=name_tag)
    return {
        "Comment": "enclavize: switch to the pending commit once its preparer says ready, "
                   "or once the wait is up",
        "StartAt": "ReadPending",
        "States": {
            # No pending means no apply in flight — a run that fired after the
            # switch was done, or after an apply unwound. Nothing to do.
            "ReadPending": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:getParameter",
                "Parameters": {"Name": pending_param},
                "ResultPath": "$.pendingParam",
                "Catch": [{"ErrorEquals": [NOT_FOUND], "Next": "NothingInFlight"}],
                "Next": "ParsePending",
            },
            "NothingInFlight": {"Type": "Succeed"},
            "ParsePending": {
                "Type": "Pass",
                "Parameters": {
                    "pending.$": "States.StringToJson($.pendingParam.Parameter.Value)",
                },
                "Next": "ReadReady",
            },
            "ReadReady": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:getParameter",
                "Parameters": {"Name": ready_param},
                "ResultPath": "$.ready",
                "Catch": [{"ErrorEquals": [NOT_FOUND], "ResultPath": "$.noReady", "Next": "Decide"}],
                "Next": "Decide",
            },
            "Decide": _decision(timeout_seconds),
            "ClearStaleReady": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:deleteParameter",
                "Parameters": {"Name": ready_param},
                "ResultPath": None,
                "Catch": [{"ErrorEquals": [NOT_FOUND], "ResultPath": "$.noReady", "Next": "NotYet"}],
                "Next": "NotYet",
            },
            "NotYet": {"Type": "Succeed"},

            # --- the switch ---------------------------------------------------
            #
            # Deleting the timer is the lock. It succeeds for exactly one run,
            # and it is the first thing here that changes anything.
            "ClaimIt": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:scheduler:deleteSchedule",
                "Parameters": {"Name": schedule_name},
                "ResultPath": None,
                "Catch": [{"ErrorEquals": [NO_SCHEDULE], "Next": "AlreadyHandled"}],
                "Next": "FindPreparer",
            },
            "AlreadyHandled": {"Type": "Succeed"},
            # A preparer that said ready has shut itself down already. One
            # that is still running is one the timeout ran out on, and it is
            # stopped before the commit it was preparing for goes in.
            "FindPreparer": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ec2:describeInstances",
                "Parameters": {
                    "Filters": [
                        {"Name": f"tag:{naming.PREPARING_FOR_TAG}",
                         "Values.$": "States.Array($.pending.commit)"},
                        {"Name": "instance-state-name", "Values": ["pending", "running"]},
                    ],
                },
                "ResultPath": "$.preparers",
                "Next": "AnyPreparer?",
            },
            "AnyPreparer?": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.preparers.Reservations[0].Instances[0].InstanceId",
                     "IsPresent": True, "Next": "StopPreparer"},
                ],
                "Default": "ClearReady",
            },
            "StopPreparer": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ec2:terminateInstances",
                "Parameters": {
                    "InstanceIds.$": "States.Array($.preparers.Reservations[0].Instances[0].InstanceId)",
                },
                "ResultPath": None,
                "Next": "ClearReady",
            },
            # Spent. The next apply clears it again before it writes anything,
            # but a word left lying around is a word that could be misread.
            "ClearReady": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:deleteParameter",
                "Parameters": {"Name": ready_param},
                "ResultPath": None,
                "Catch": [{"ErrorEquals": [NOT_FOUND], "ResultPath": "$.noReady", "Next": "RenderNew"}],
                "Next": "RenderNew",
            },
            "RenderNew": {
                "Type": "Pass",
                "Parameters": {
                    "userData.$": user_data_expression(
                        app_repo=app_repo, domain=domain, mode=NEW, commit_path="$.pending.commit",
                    ),
                },
                "ResultPath": "$.new",
                "Next": "LaunchNew",
            },
            "LaunchNew": dict(
                run_instances(
                    **launch, user_data_path="$.new.userData", commit_path="$.pending.commit",
                    next_state="DescribeLaunched",
                ),
                Catch=[{"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure",
                        "Next": "ClearPendingAfterFailure"}],
            ),
            "DescribeLaunched": {
                "Type": "Pass",
                "Parameters": {
                    "commit.$": "$.pending.commit",
                    "instanceId.$": "$.launch.instanceId",
                    "startedAt.$": "$.pending.at",
                    "since.$": "$$.State.EnteredTime",
                    "recordKey.$": "$.pending.recordKey",
                },
                "ResultPath": "$.serving",
                "Next": "WriteCurrent",
            },
            # From here the new version is what the account says is serving.
            # Everything after is tidying, and is skipped rather than allowed
            # to undo a switch that happened.
            "WriteCurrent": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:putParameter",
                "Parameters": {
                    "Name": current_param,
                    "Value.$": "States.JsonToString($.serving)",
                    "Type": "String",
                    "Overwrite": True,
                },
                "Retry": [PARAMETER_RETRY],
                "ResultPath": None,
                "Next": "ClearPending",
            },
            "ClearPending": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:deleteParameter",
                "Parameters": {"Name": pending_param},
                "ResultPath": None,
                "Catch": _tidy("RetireOldRecord"),
                "Next": "RetireOldRecord",
            },
            "RetireOldRecord": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Parameters": {
                    "Bucket": dashboard_bucket,
                    "Key.$": "$.pending.previous.recordKey",
                    "ContentType": "application/json",
                    "CacheControl": naming.CHANGES_CACHE_CONTROL,
                    "Body": {
                        "commit.$": "$.pending.previous.commit",
                        "startedAt.$": "$.pending.previous.startedAt",
                        "status": "retired",
                        "instanceId.$": "$.pending.previous.instanceId",
                        "retiredAt.$": "$.serving.since",
                        "replacedBy.$": "$.pending.commit",
                    },
                },
                "ResultPath": None,
                "Catch": _tidy("UpdateRecord"),
                "Next": "UpdateRecord",
            },
            "UpdateRecord": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Parameters": {
                    "Bucket": dashboard_bucket,
                    "Key.$": "$.pending.recordKey",
                    "ContentType": "application/json",
                    "CacheControl": naming.CHANGES_CACHE_CONTROL,
                    "Body": {
                        "commit.$": "$.pending.commit",
                        "startedAt.$": "$.pending.at",
                        "status": "launched",
                        "instanceId.$": "$.serving.instanceId",
                        "since.$": "$.serving.since",
                        "previous.$": "$.pending.previous.commit",
                    },
                },
                "ResultPath": None,
                "Catch": _tidy("Done"),
                "Next": "Done",
            },
            "Done": {"Type": "Succeed"},

            # --- the launch failed: the serving version stays ----------------
            #
            # Pending goes so the account is not left refusing every apply for
            # a switch that will never come.
            "ClearPendingAfterFailure": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:deleteParameter",
                "Parameters": {"Name": pending_param},
                "ResultPath": None,
                "Catch": _tidy("RecordFailure"),
                "Next": "RecordFailure",
            },
            "RecordFailure": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Parameters": {
                    "Bucket": dashboard_bucket,
                    "Key.$": "$.pending.recordKey",
                    "ContentType": "application/json",
                    "CacheControl": naming.CHANGES_CACHE_CONTROL,
                    "Body": {
                        "commit.$": "$.pending.commit",
                        "startedAt.$": "$.pending.at",
                        "status": "failed",
                        "previous.$": "$.pending.previous.commit",
                        "error.$": "$.failure.Error",
                        "cause.$": "$.failure.Cause",
                    },
                },
                "ResultPath": None,
                "Catch": _tidy("CouldNotLaunch"),
                "Next": "CouldNotLaunch",
            },
            "CouldNotLaunch": {
                "Type": "Fail",
                "ErrorPath": "$.failure.Error",
                "CausePath": "$.failure.Cause",
            },
        },
    }
