"""The receiving state machine's definition, as data.

This is what the apply API starts, synchronously, and it decides and nothing
more: is a switch already pending or under way, and is anything serving yet.
The first refuses the apply. The second picks between starting the switch now
and scheduling it for later, and in the delayed case the version currently
serving is told what is coming. The switch itself is another machine's job —
see switchmachine.py — because it can run for an hour, and this one has to
answer inside API Gateway's 29 seconds.

"In flight" is read off the things themselves — the one-time schedule, and the
switch machine's running executions — rather than off a marker. A switch that
died holds no slot that way, so a crash can never leave the account refusing
every apply for good.

**The record is also the dashboard's only source of history.** A sealed account
runs nothing on a schedule, and a static page cannot list a bucket, so the index
the dashboard reads has to be written by whatever runs on each apply — which is
this. It is rebuilt from listings rather than appended to, for two reasons: a
listing is idempotent, so a half-written index heals itself on the next apply
instead of drifting; and the Amazon States Language has no way to append to an
array at all, having no ArrayConcat.
"""

from . import naming

_KEEP_GOING = [
    {"ErrorEquals": ["States.ALL"], "ResultPath": "$.indexError", "Next": "Done"}
]
"""Everything after the decision is bookkeeping, and must not fail the apply.

By the time these states run the switch has been started or scheduled. Letting a
listing hiccup fail the execution would have the API report a failed apply for
work that is going ahead regardless — the worst of both answers. The ResultPath
is what keeps the decision's own output alive for Done to answer with.
"""

def _when_to_switch(delay_seconds: int) -> str:
    """The one JSONata expression in the definition.

    JSONPath's intrinsics cannot add to a timestamp, and a one-time schedule
    needs one: `at(yyyy-mm-ddThh:mm:ss)`, evaluated in UTC. So this one state
    speaks JSONata, and hands everything the delayed branch needs back as plain
    values — the ISO switch time, the schedule expression, and the two JSON
    strings that Parameter Store and the schedule's target want.
    """
    return (
        "{% ("
        f"$when := $toMillis($states.input.at) + {delay_seconds * 1000}; "
        "$switchAt := $fromMillis($when); "
        "$merge([$states.input, {"
        "'outcome': {'status': 'scheduled', 'switchAt': $switchAt}, "
        "'schedule': {"
        "'expression': 'at(' & $fromMillis($when, '[Y0001]-[M01]-[D01]T[H01]:[m01]:[s01]') & ')', "
        "'pendingValue': $string({'commit': $states.input.commit, 'switchAt': $switchAt}), "
        "'input': $string({'commit': $states.input.commit, 'at': $states.input.at, 'immediate': false})"
        "}}])"
        ") %}"
    )


def build_definition(
    *,
    dashboard_bucket: str,
    switch_state_machine_arn: str,
    schedule_name: str,
    scheduler_role_arn: str,
    current_param: str,
    pending_param: str,
    delay_seconds: int,
    in_flight_error: str,
) -> dict:
    """An Express definition that decides, records, and answers.

    The commit is the only value taken from the request, and it has already been
    checked against a 40-hex pattern by the API's request validator before it
    can reach here. `in_flight_error` is the error name the API's response
    template turns into a 409, so the two are handed the same string.
    """
    return {
        "Comment": "enclavize: accept a commit and start or schedule its switch",
        "StartAt": "Stamp",
        "States": {
            "Stamp": {
                "Type": "Pass",
                "Parameters": {
                    "commit.$": "$.commit",
                    # Stamped once and used by everything downstream. Read
                    # afresh in each state it would drift by milliseconds, and
                    # an apply landing on the last millisecond of a month would
                    # be filed under the next one.
                    "at.$": "$$.State.EnteredTime",
                },
                "Next": "AnySwitchRunning",
            },
            "AnySwitchRunning": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:sfn:listExecutions",
                "Parameters": {
                    "StateMachineArn": switch_state_machine_arn,
                    "StatusFilter": "RUNNING",
                    "MaxResults": 1,
                },
                "ResultPath": "$.running",
                "Next": "AnyScheduled",
            },
            "AnyScheduled": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:scheduler:getSchedule",
                "Parameters": {"Name": schedule_name},
                "ResultPath": "$.scheduled",
                "Catch": [
                    {
                        "ErrorEquals": ["Scheduler.ResourceNotFoundException"],
                        "ResultPath": "$.noSchedule",
                        "Next": "Busy?",
                    }
                ],
                "Next": "Busy?",
            },
            "Busy?": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.running.Executions[0]", "IsPresent": True,
                     "Next": "RefuseInFlight"},
                    {"Variable": "$.scheduled.Arn", "IsPresent": True, "Next": "RefuseInFlight"},
                ],
                "Default": "AnyCurrent",
            },
            "RefuseInFlight": {
                "Type": "Fail",
                "Error": in_flight_error,
                "Cause": "an apply is already pending or switching; wait for it to finish",
            },
            "AnyCurrent": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:getParameter",
                "Parameters": {"Name": current_param},
                "ResultPath": "$.current",
                "Catch": [
                    {
                        "ErrorEquals": ["Ssm.ParameterNotFoundException"],
                        "ResultPath": "$.noCurrent",
                        "Next": "First?",
                    }
                ],
                "Next": "First?",
            },
            # Nothing serving means nobody to warn and nothing to protect, so
            # the first apply after a bring-up switches at once.
            "First?": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.current.Parameter.Value", "IsPresent": True,
                     "Next": "WhenToSwitch"},
                ],
                "Default": "SwitchNow",
            },
            "SwitchNow": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution",
                "Parameters": {
                    "StateMachineArn": switch_state_machine_arn,
                    "Input": {"commit.$": "$.commit", "at.$": "$.at", "immediate": True},
                },
                "ResultPath": "$.started",
                "Next": "DescribeSwitching",
            },
            "DescribeSwitching": {
                "Type": "Pass",
                "Parameters": {"status": "switching", "switchAt.$": "$.at"},
                "ResultPath": "$.outcome",
                "Next": "RecordApply",
            },
            "WhenToSwitch": {
                "Type": "Pass",
                "QueryLanguage": "JSONata",
                "Output": _when_to_switch(delay_seconds),
                "Next": "WritePending",
            },
            # Written before the schedule exists, so the version serving learns
            # what is coming even if scheduling then fails — in which case the
            # apply fails too, and the next one overwrites this.
            "WritePending": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:putParameter",
                "Parameters": {
                    "Name": pending_param,
                    "Value.$": "$.schedule.pendingValue",
                    "Type": "String",
                    "Overwrite": True,
                },
                "ResultPath": None,
                "Next": "CreateSchedule",
            },
            "CreateSchedule": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:scheduler:createSchedule",
                "Parameters": {
                    "Name": schedule_name,
                    "Description": "enclavize: the switch this apply is waiting for",
                    "ScheduleExpression.$": "$.schedule.expression",
                    "ScheduleExpressionTimezone": "UTC",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    # Gone once it has fired, which is what lets the next apply
                    # tell "pending" from "already started" by its absence.
                    "ActionAfterCompletion": "DELETE",
                    "Target": {
                        "Arn": switch_state_machine_arn,
                        "RoleArn": scheduler_role_arn,
                        "Input.$": "$.schedule.input",
                    },
                },
                "ResultPath": None,
                "Next": "RecordApply",
            },
            # One object per apply, rewritten by the switch as it goes: the
            # timestamp in the key is what makes applying the same commit twice
            # two records rather than one.
            "RecordApply": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Parameters": {
                    "Bucket": dashboard_bucket,
                    "Key.$": (
                        f"States.Format('{naming.APPLIES_PREFIX}{{}}_{{}}.json', $.at, $.commit)"
                    ),
                    "ContentType": "application/json",
                    "CacheControl": naming.CHANGES_CACHE_CONTROL,
                    "Body": {
                        "commit.$": "$.commit",
                        "startedAt.$": "$.at",
                        "status.$": "$.outcome.status",
                        "switchAt.$": "$.outcome.switchAt",
                    },
                },
                "ResultPath": None,
                "Catch": _KEEP_GOING,
                "Next": "WhichMonth",
            },
            # The year and month out of the timestamp. Because record keys open
            # with that timestamp, it is also the prefix of everything applied
            # that month — so a month is one listing, with no pagination, no
            # counter and no loop.
            "WhichMonth": {
                "Type": "Pass",
                "Parameters": {
                    "name.$": (
                        "States.Format('{}-{}', "
                        "States.ArrayGetItem(States.StringSplit($.at, '-'), 0), "
                        "States.ArrayGetItem(States.StringSplit($.at, '-'), 1))"
                    ),
                },
                "ResultPath": "$.month",
                "Next": "ListMonth",
            },
            "ListMonth": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:s3:listObjectsV2",
                "Parameters": {
                    "Bucket": dashboard_bucket,
                    "Prefix.$": f"States.Format('{naming.APPLIES_PREFIX}{{}}', $.month.name)",
                },
                "ResultPath": "$.page",
                "Catch": _KEEP_GOING,
                "Next": "WriteMonthIndex",
            },
            "WriteMonthIndex": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Parameters": {
                    "Bucket": dashboard_bucket,
                    "Key.$": (
                        f"States.Format('{naming.APPLIES_INDEX_PREFIX}{{}}.json', $.month.name)"
                    ),
                    "ContentType": "application/json",
                    "CacheControl": naming.CHANGES_CACHE_CONTROL,
                    "Body": {
                        "month.$": "$.month.name",
                        "generatedAt.$": "$.at",
                        # A listing caps at a thousand keys and this makes no
                        # second call, so a month busier than that is carried
                        # through as truncated rather than quietly shortened.
                        "truncated.$": "$.page.IsTruncated",
                        "applies.$": "$.page.Contents",
                    },
                },
                "ResultPath": None,
                "Catch": _KEEP_GOING,
                "Next": "ListMonths",
            },
            "ListMonths": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:s3:listObjectsV2",
                "Parameters": {
                    "Bucket": dashboard_bucket,
                    "Prefix": naming.APPLIES_INDEX_PREFIX,
                },
                "ResultPath": "$.months",
                "Catch": _KEEP_GOING,
                "Next": "WriteManifest",
            },
            "WriteManifest": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Parameters": {
                    "Bucket": dashboard_bucket,
                    "Key": naming.APPLIES_MANIFEST_KEY,
                    "ContentType": "application/json",
                    "CacheControl": naming.CHANGES_CACHE_CONTROL,
                    "Body": {
                        "generatedAt.$": "$.at",
                        "months.$": "$.months.Contents",
                    },
                },
                "ResultPath": None,
                "Catch": _KEEP_GOING,
                "Next": "Done",
            },
            "Done": {
                "Type": "Pass",
                "Parameters": {
                    "commit.$": "$.commit",
                    # "switching" or "scheduled", never "applied": the switch
                    # has only just started, or not yet. The dashboard is where
                    # it is watched.
                    "status.$": "$.outcome.status",
                    "switchAt.$": "$.outcome.switchAt",
                },
                "End": True,
            },
        },
    }
