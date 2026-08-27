"""The apply state machine's definition, as data.

It does two things: launch an instance that will clone the app and run it, then
write down that it did. It deliberately does not wait for the commit to finish
applying — an Express workflow tops out at five minutes and API Gateway's
integration at 29 seconds, while a real apply takes longer than both. Progress
is watched on the dashboard instead.

The user-data template is rendered by the state machine rather than baked in,
so the commit reaches the instance without a Lambda in the path.

**The record is also the dashboard's only source of history.** A sealed account
runs nothing on a schedule, and a static page cannot list a bucket, so the index
the dashboard reads has to be written by whatever runs on each apply — which is
this. It is rebuilt from listings rather than appended to, for two reasons: a
listing is idempotent, so a half-written index heals itself on the next apply
instead of drifting; and the Amazon States Language has no way to append to an
array at all, having no ArrayConcat.
"""

from . import naming

# Instance-profile propagation reaches this launch too, so the state machine
# retries it the same way the sealing launch does.
_PROFILE_RETRY = {
    "ErrorEquals": ["Ec2.Ec2Exception", "States.TaskFailed"],
    "IntervalSeconds": 3,
    "MaxAttempts": 20,
    "BackoffRate": 1.0,
}

_KEEP_GOING = [
    {"ErrorEquals": ["States.ALL"], "ResultPath": "$.indexError", "Next": "Done"}
]
"""Everything after the launch is bookkeeping, and must not fail the apply.

By the time these states run the instance is already up and applying the commit.
Letting a listing hiccup fail the execution would have the API report a failed
apply for work that is going ahead regardless — the worst of both answers. The
ResultPath is what keeps the launch's own output alive for Done to answer with.
"""


def build_definition(
    *,
    app_repo: str,
    domain: str,
    image_id: str,
    instance_type: str,
    subnet_id: str,
    instance_profile: str,
    dashboard_bucket: str,
    name_tag: str,
) -> dict:
    """An Express definition that renders user-data, launches, and records.

    The commit is the only value taken from the request, and it has already been
    checked against a 40-hex pattern by the API's request validator before it
    can reach here.
    """
    # PLACEHOLDER marks where the commit is substituted; everything else is
    # literal text that escape_for_format has to protect.
    #
    # The domain is the whole of what an application is handed, because it is the
    # whole of what an application cannot work out for itself. A region would say
    # enclavize can be pointed at more than one, and it cannot; the commit is
    # already what the repo was checked out at.
    user_data_template = "\n".join(
        [
            "#!/bin/bash",
            "set -euxo pipefail",
            "dnf install -y git",
            "rm -rf /opt/app",
            f"git clone https://github.com/{app_repo}.git /opt/app",
            "cd /opt/app",
            f"git checkout {PLACEHOLDER}",
            "set +x",
            f"export ENCLAVIZE_DOMAIN={domain}",
            "exec ./setup.sh",
            "",
        ]
    )

    return {
        "Comment": "enclavize: launch one instance to apply a commit",
        "StartAt": "RenderUserData",
        "States": {
            "RenderUserData": {
                "Type": "Pass",
                "Parameters": {
                    "commit.$": "$.commit",
                    # Stamped once and used by everything downstream. Read
                    # afresh in each state it would drift by milliseconds, and
                    # an apply landing on the last millisecond of a month would
                    # be filed under the next one.
                    "at.$": "$$.State.EnteredTime",
                    "userData.$": (
                        f"States.Base64Encode(States.Format('{escape_for_format(user_data_template)}', "
                        "$.commit))"
                    ),
                },
                "Next": "LaunchInstance",
            },
            "LaunchInstance": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ec2:runInstances",
                "Parameters": {
                    "ImageId": image_id,
                    "InstanceType": instance_type,
                    "MinCount": 1,
                    "MaxCount": 1,
                    "SubnetId": subnet_id,
                    "IamInstanceProfile": {"Name": instance_profile},
                    "UserData.$": "$.userData",
                    "TagSpecifications": [
                        {
                            "ResourceType": "instance",
                            "Tags": [
                                {"Key": "Name", "Value": name_tag},
                                {"Key": "enclavize:commit", "Value.$": "$.commit"},
                            ],
                        }
                    ],
                },
                "Retry": [_PROFILE_RETRY],
                "ResultPath": "$.launch",
                "Next": "RecordApply",
            },
            # One object per apply, never overwritten: the timestamp in the key
            # is what makes applying the same commit twice two records rather
            # than one.
            "RecordApply": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Parameters": {
                    "Bucket": dashboard_bucket,
                    "Key.$": (
                        f"States.Format('{naming.APPLIES_PREFIX}{{}}_{{}}.json', $.at, $.commit)"
                    ),
                    "ContentType": "application/json",
                    "Body": {
                        "commit.$": "$.commit",
                        "instanceId.$": "$.launch.Instances[0].InstanceId",
                        "startedAt.$": "$.at",
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
                    "instanceId.$": "$.launch.Instances[0].InstanceId",
                    # Deliberately not "deployed": the instance has only just
                    # started. The dashboard is where progress is watched.
                    "status": "launched",
                },
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
