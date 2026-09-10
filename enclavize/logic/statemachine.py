"""The receiving state machine's definition, as data.

This is what the apply API starts, synchronously, and it has to answer inside
API Gateway's 29 seconds. So it decides and launches, and never waits: is an
apply already in flight, and is anything serving yet. The first refuses. The
second picks between two launches.

Nothing serving: the commit is launched at once, in NEW mode, and written down
as what is serving. Something serving: the *serving* commit is launched again
on a preparing instance, in UPDATE mode, told which commit is coming — and a
timer is set to look every few minutes for that instance's word that it is
ready. The look, and the switch it leads to, are another machine's job (see
checkmachine.py); this one only arranges them.

"In flight" is read off the things themselves — the timer, and the check
machine's running executions — rather than off a marker. A check that died
holds no slot that way, so a crash can never leave the account refusing every
apply for good.

The user-data template is rendered by the state machine rather than baked in,
so the commit reaches the instance without a Lambda in the path.

**The record is also the dashboard's only source of history.** A sealed account
runs nothing on a schedule of its own, and a static page cannot list a bucket,
so the index the dashboard reads has to be written by whatever runs on each
apply — which is this. It is rebuilt from listings rather than appended to, for
two reasons: a listing is idempotent, so a half-written index heals itself on
the next apply instead of drifting; and the Amazon States Language has no way
to append to an array at all, having no ArrayConcat.
"""

from . import naming

NEW = "NEW"
UPDATE = "UPDATE"
"""The two modes an application's setup.sh is run in. NEW: this instance is
the version that will serve. UPDATE: this instance runs the serving commit
once more, to prepare for the one coming; it does what it must, says ready,
and shuts itself down."""

# Instance-profile propagation reaches this launch too, so the state machine
# retries it the same way the sealing launch does.
PROFILE_RETRY = {
    "ErrorEquals": ["Ec2.Ec2Exception", "States.TaskFailed"],
    "IntervalSeconds": 3,
    "MaxAttempts": 20,
    "BackoffRate": 1.0,
}

# Parameter Store is the account's memory of what is serving; a hiccup writing
# it is worth a few more tries before the apply is failed.
PARAMETER_RETRY = {"ErrorEquals": ["States.ALL"], "IntervalSeconds": 5, "MaxAttempts": 3}

NOT_FOUND = "Ssm.ParameterNotFoundException"
NO_SCHEDULE = "Scheduler.ResourceNotFoundException"

_KEEP_GOING = [
    {"ErrorEquals": ["States.ALL"], "ResultPath": "$.indexError", "Next": "Done"}
]
"""Everything after the launch is bookkeeping, and must not fail the apply.

By the time these states run the instance is up. Letting a listing hiccup fail
the execution would have the API report a failed apply for work that is going
ahead regardless — the worst of both answers. The ResultPath is what keeps the
launch's own output alive for Done to answer with.
"""

_KEEP_GOING_JSONATA = [
    {
        "ErrorEquals": ["States.ALL"],
        "Output": "{% $merge([$states.input, {'indexError': $states.errorOutput}]) %}",
        "Next": "Done",
    }
]
"""The same rule for a JSONata state, which has no ResultPath: the input is
carried through by hand, with the error beside it."""


def _keys_of(listing: str) -> str:
    """The keys of an S3 listing, as an array, whatever the listing holds.

    The brackets are what make it an array every time. JSONata unwraps a path
    that yields one value — a month with a single apply would come out as a
    bare string, not a one-element list — and a listing with nothing in it has
    no Contents at all, which the path turns into nothing and the brackets turn
    into an empty array. Without them the first apply of a month would break
    the page that reads it.
    """
    return f"{{% [{listing}.Contents.Key] %}}"


def user_data_expression(*, app_repo: str, domain: str, mode: str, commit_path: str,
                         next_commit_path: str = "") -> str:
    """The intrinsic that renders an instance's user-data, for either mode.

    `commit_path` is where the commit to check out sits in the state; in UPDATE
    mode `next_commit_path` is where the one being prepared for sits. Both are
    substituted into the script by States.Format, everything else is literal
    text that escape_for_format has to protect.

    The environment is the whole of what an application is handed, because it
    is the whole of what it cannot work out for itself: the domain, which mode
    it is in, and — only when preparing — what it is preparing for. A region
    would say enclavize can be pointed at more than one, and it cannot; the
    commit is already what the repo was checked out at.
    """
    lines = [
        "#!/bin/bash",
        "set -euxo pipefail",
        "dnf install -y git",
        "rm -rf /opt/app",
        f"git clone https://github.com/{app_repo}.git /opt/app",
        "cd /opt/app",
        f"git checkout {PLACEHOLDER}",
        "set +x",
        f"export ENCLAVIZE_DOMAIN={domain}",
        f"export ENCLAVIZE_MODE={mode}",
    ]
    arguments = [commit_path]
    if mode == UPDATE:
        lines.append(f"export ENCLAVIZE_NEXT_COMMIT={PLACEHOLDER}")
        arguments.append(next_commit_path)
    lines += ["exec ./setup.sh", ""]
    template = escape_for_format("\n".join(lines))
    return f"States.Base64Encode(States.Format('{template}', {', '.join(arguments)}))"


def run_instances(*, image_id: str, instance_type: str, subnet_id: str, instance_profile: str,
                  name_tag: str, user_data_path: str, commit_path: str, preparing_for_path: str = "",
                  next_state: str) -> dict:
    """One instance, with the bounded profile and the enclave's tags.

    A preparing instance is set to terminate when it shuts down: the
    application ends its preparation with a shutdown, and there is nothing to
    keep — the instance ran the commit already serving, for its say and
    nothing else.
    """
    tags = [
        {"Key": "Name", "Value": name_tag},
        {"Key": naming.COMMIT_TAG, "Value.$": commit_path},
    ]
    parameters = {
        "ImageId": image_id,
        "InstanceType": instance_type,
        "MinCount": 1,
        "MaxCount": 1,
        "SubnetId": subnet_id,
        "IamInstanceProfile": {"Name": instance_profile},
        "UserData.$": user_data_path,
        "TagSpecifications": [{"ResourceType": "instance", "Tags": tags}],
    }
    if preparing_for_path:
        tags.append({"Key": naming.PREPARING_FOR_TAG, "Value.$": preparing_for_path})
        parameters["InstanceInitiatedShutdownBehavior"] = "terminate"
    return {
        "Type": "Task",
        "Resource": "arn:aws:states:::aws-sdk:ec2:runInstances",
        "Parameters": parameters,
        "Retry": [PROFILE_RETRY],
        "ResultSelector": {"instanceId.$": "$.Instances[0].InstanceId"},
        "ResultPath": "$.launch",
        "Next": next_state,
    }


def rate_expression(minutes: int) -> str:
    """How EventBridge Scheduler spells 'every N minutes'."""
    return f"rate({minutes} minute{'' if minutes == 1 else 's'})"


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
    check_state_machine_arn: str,
    schedule_name: str,
    scheduler_role_arn: str,
    check_interval_minutes: int,
    current_param: str,
    pending_param: str,
    ready_param: str,
    in_flight_error: str,
) -> dict:
    """An Express definition that decides, launches, records, and answers.

    The commit is the only value taken from the request, and it has already been
    checked against a 40-hex pattern by the API's request validator before it
    can reach here. `in_flight_error` is the error name the API's response
    template turns into a 409, so the two are handed the same string.
    """
    launch = dict(image_id=image_id, instance_type=instance_type, subnet_id=subnet_id,
                  instance_profile=instance_profile, name_tag=name_tag)
    return {
        "Comment": "enclavize: accept a commit and launch it, or a preparer for it",
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
                    # One object per apply, never overwritten by another: the
                    # timestamp in the key is what makes applying the same
                    # commit twice two records rather than one.
                    "recordKey.$": (
                        f"States.Format('{naming.APPLIES_PREFIX}{{}}_{{}}.json', "
                        "$$.State.EnteredTime, $.commit)"
                    ),
                },
                "Next": "AnyScheduled",
            },
            # The timer stands while an apply waits on its preparer; the check
            # machine runs while one is being switched. Either is an apply in
            # flight, and a second one would overwrite what the first wrote.
            "AnyScheduled": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:scheduler:getSchedule",
                "Parameters": {"Name": schedule_name},
                "ResultPath": "$.scheduled",
                "Catch": [
                    {"ErrorEquals": [NO_SCHEDULE], "ResultPath": "$.noSchedule",
                     "Next": "AnyCheckRunning"}
                ],
                "Next": "AnyCheckRunning",
            },
            "AnyCheckRunning": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:sfn:listExecutions",
                "Parameters": {
                    "StateMachineArn": check_state_machine_arn,
                    "StatusFilter": "RUNNING",
                    "MaxResults": 1,
                },
                "ResultPath": "$.running",
                "Next": "Busy?",
            },
            "Busy?": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.scheduled.Arn", "IsPresent": True, "Next": "RefuseInFlight"},
                    {"Variable": "$.running.Executions[0]", "IsPresent": True,
                     "Next": "RefuseInFlight"},
                ],
                "Default": "AnyCurrent",
            },
            "RefuseInFlight": {
                "Type": "Fail",
                "Error": in_flight_error,
                "Cause": "an apply is already preparing or switching; wait for it to finish",
            },
            "AnyCurrent": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:getParameter",
                "Parameters": {"Name": current_param},
                "ResultPath": "$.current",
                "Catch": [
                    {"ErrorEquals": [NOT_FOUND], "ResultPath": "$.noCurrent", "Next": "First?"}
                ],
                "Next": "First?",
            },
            # Nothing serving means nobody to prepare, so the first apply
            # after a bring-up launches the commit itself, at once.
            "First?": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.current.Parameter.Value", "IsPresent": True,
                     "Next": "Prepare"},
                ],
                "Default": "RenderNew",
            },

            # --- nothing serving: launch the commit ------------------------
            "RenderNew": {
                "Type": "Pass",
                "Parameters": {
                    "commit.$": "$.commit",
                    "at.$": "$.at",
                    "recordKey.$": "$.recordKey",
                    "userData.$": user_data_expression(
                        app_repo=app_repo, domain=domain, mode=NEW, commit_path="$.commit",
                    ),
                },
                "Next": "LaunchNew",
            },
            "LaunchNew": run_instances(
                **launch, user_data_path="$.userData", commit_path="$.commit",
                next_state="DescribeLaunched",
            ),
            # What the account will say is serving, from here until the next
            # switch. The record key rides along so the switch can retire the
            # record when the time comes.
            "DescribeLaunched": {
                "Type": "Pass",
                "Parameters": {
                    "commit.$": "$.commit",
                    "instanceId.$": "$.launch.instanceId",
                    "startedAt.$": "$.at",
                    "since.$": "$.at",
                    "recordKey.$": "$.recordKey",
                },
                "ResultPath": "$.serving",
                "Next": "WriteCurrent",
            },
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
                "Next": "RecordLaunched",
            },
            "RecordLaunched": {
                "Type": "Pass",
                "Parameters": {
                    "commit.$": "$.commit",
                    "startedAt.$": "$.at",
                    # Deliberately not "applied": the instance has only just
                    # started. The dashboard is where progress is watched.
                    "status": "launched",
                    "instanceId.$": "$.launch.instanceId",
                },
                "ResultPath": "$.record",
                "Next": "RecordApply",
            },

            # --- something serving: launch a preparer for the commit ---------
            #
            # Everything the check machine will need is put into the pending
            # parameter, because the timer starts it with no input at all.
            "Prepare": {
                "Type": "Pass",
                "Parameters": {
                    "commit.$": "$.commit",
                    "at.$": "$.at",
                    "recordKey.$": "$.recordKey",
                    "pending": {
                        "commit.$": "$.commit",
                        "at.$": "$.at",
                        "recordKey.$": "$.recordKey",
                        "previous.$": "States.StringToJson($.current.Parameter.Value)",
                    },
                },
                "Next": "RenderPreparer",
            },
            "RenderPreparer": {
                "Type": "Pass",
                "Parameters": {
                    "userData.$": user_data_expression(
                        app_repo=app_repo, domain=domain, mode=UPDATE,
                        commit_path="$.pending.previous.commit", next_commit_path="$.commit",
                    ),
                },
                "ResultPath": "$.preparer",
                "Next": "ClearStaleReady",
            },
            # A ready left over from an earlier apply must not count for this
            # one. Cleared before anything else is written, so the order the
            # preparer relies on holds: by the time it can say ready, pending
            # and the timer are both in place.
            "ClearStaleReady": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:deleteParameter",
                "Parameters": {"Name": ready_param},
                "ResultPath": None,
                "Catch": [
                    {"ErrorEquals": [NOT_FOUND], "ResultPath": "$.noReady", "Next": "WritePending"}
                ],
                "Next": "WritePending",
            },
            "WritePending": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:putParameter",
                "Parameters": {
                    "Name": pending_param,
                    "Value.$": "States.JsonToString($.pending)",
                    "Type": "String",
                    "Overwrite": True,
                },
                "Retry": [PARAMETER_RETRY],
                "ResultPath": None,
                "Next": "CreateSchedule",
            },
            # Recurring, and deleted by the check machine rather than by
            # itself: its standing is what says an apply is in flight, and
            # deleting it is how the check claims the switch.
            "CreateSchedule": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:scheduler:createSchedule",
                "Parameters": {
                    "Name": schedule_name,
                    "Description": "enclavize: look for the preparing instance's word that it is ready",
                    "ScheduleExpression": rate_expression(check_interval_minutes),
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "ActionAfterCompletion": "NONE",
                    "Target": {
                        "Arn": check_state_machine_arn,
                        "RoleArn": scheduler_role_arn,
                        "Input": "{}",
                    },
                },
                "ResultPath": None,
                "Catch": [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure",
                           "Next": "UnwindPending"}],
                "Next": "LaunchPreparer",
            },
            # Last, so that by the time the preparer can say ready, everything
            # that has to hear it is in place.
            "LaunchPreparer": dict(
                run_instances(
                    **launch, user_data_path="$.preparer.userData",
                    commit_path="$.pending.previous.commit", preparing_for_path="$.commit",
                    next_state="RecordPreparing",
                ),
                Catch=[{"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure",
                        "Next": "UnwindSchedule"}],
            ),
            "RecordPreparing": {
                "Type": "Pass",
                "Parameters": {
                    "commit.$": "$.commit",
                    "startedAt.$": "$.at",
                    "status": "preparing",
                    "previous.$": "$.pending.previous.commit",
                    "preparerId.$": "$.launch.instanceId",
                },
                "ResultPath": "$.record",
                "Next": "RecordApply",
            },
            # A preparer that never launched must not leave the timer and the
            # pending behind it: the timer would count seven days towards a
            # switch nobody is preparing for, refusing every apply meanwhile.
            "UnwindSchedule": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:scheduler:deleteSchedule",
                "Parameters": {"Name": schedule_name},
                "ResultPath": None,
                "Catch": [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.unwindError",
                           "Next": "UnwindPending"}],
                "Next": "UnwindPending",
            },
            "UnwindPending": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:deleteParameter",
                "Parameters": {"Name": pending_param},
                "ResultPath": None,
                "Catch": [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.unwindError",
                           "Next": "CouldNotPrepare"}],
                "Next": "CouldNotPrepare",
            },
            "CouldNotPrepare": {
                "Type": "Fail",
                "ErrorPath": "$.failure.Error",
                "CausePath": "$.failure.Cause",
            },

            # --- bookkeeping, shared by both ---------------------------------
            "RecordApply": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Parameters": {
                    "Bucket": dashboard_bucket,
                    "Key.$": "$.recordKey",
                    "ContentType": "application/json",
                    # Rewritten by the check machine as the switch goes, so it
                    # must not be cached like the objects written once.
                    "CacheControl": naming.CHANGES_CACHE_CONTROL,
                    "Body.$": "$.record",
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
            # The two index writers speak JSONata: a listing comes back as
            # objects full of ETags and storage classes, and the page wants
            # only the keys. JSONPath has no way to pick one field out of each
            # item; JSONata does it in a path. Square brackets around the path
            # are load-bearing — see _keys_of.
            "WriteMonthIndex": {
                "Type": "Task",
                "QueryLanguage": "JSONata",
                "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Arguments": {
                    "Bucket": dashboard_bucket,
                    "Key": f"{{% '{naming.APPLIES_INDEX_PREFIX}' & $states.input.month.name & '.json' %}}",
                    "ContentType": "application/json",
                    "CacheControl": naming.CHANGES_CACHE_CONTROL,
                    "Body": {
                        "month": "{% $states.input.month.name %}",
                        "generatedAt": "{% $states.input.at %}",
                        # A listing caps at a thousand keys and this makes no
                        # second call, so a month busier than that is carried
                        # through as truncated rather than quietly shortened.
                        "truncated": "{% $states.input.page.IsTruncated ? true : false %}",
                        "applies": _keys_of("$states.input.page"),
                    },
                },
                "Output": "{% $states.input %}",
                "Catch": _KEEP_GOING_JSONATA,
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
                "QueryLanguage": "JSONata",
                "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Arguments": {
                    "Bucket": dashboard_bucket,
                    "Key": naming.APPLIES_MANIFEST_KEY,
                    "ContentType": "application/json",
                    "CacheControl": naming.CHANGES_CACHE_CONTROL,
                    "Body": {
                        "generatedAt": "{% $states.input.at %}",
                        "months": _keys_of("$states.input.months"),
                    },
                },
                "Output": "{% $states.input %}",
                "Catch": _KEEP_GOING_JSONATA,
                "Next": "Done",
            },
            # The answer is the record, exactly as the dashboard will show it:
            # launched with the instance, or preparing with what came before.
            "Done": {
                "Type": "Pass",
                "OutputPath": "$.record",
                "End": True,
            },
        },
    }


PLACEHOLDER = "\x00"
"""Stands in for a States.Format {} slot while the literal text is escaped."""


def escape_for_format(template: str) -> str:
    """Escape literal text for a States.Format argument.

    The Amazon States Language reserves ' { } and \\ inside an intrinsic
    invocation and requires each to be preceded by a backslash. json.dumps then
    doubles those backslashes when the definition is serialised, which is what
    the JSON form of the rules calls for.

    Placeholders are carried through as a sentinel so that genuine braces in the
    script are escaped while the {} slots survive.
    """
    escaped = (
        template.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("{", "\\{")
        .replace("}", "\\}")
    )
    return escaped.replace(PLACEHOLDER, "{}")
