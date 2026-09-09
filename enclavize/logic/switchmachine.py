"""The switching state machine's definition, as data.

Started by the receiving machine — at once for the first apply, or by the
one-time schedule for every later one — and Standard rather than Express,
because it waits: for an instance to run, for it to pass health checks, for the
old one to drain. An hour is possible and five minutes is not enough.

The order is the guarantee. The new version goes on the listener at weight zero
first, because the load balancer checks only the target groups a listener rule
names, and a group hanging off nothing stays `unused` forever. Traffic moves in
one listener change, and only from the branch that saw `healthy` — the balancer
would not stop it moving earlier: a group whose only target is unhealthy is
sent traffic anyway, and nothing falls back to the other weighted group on its
own. The old version is taken out only after the new one is in.

Anything that fails before the switch tears down what it built and leaves the
current version exactly where it was. Anything that fails after the switch is
tidying, and is skipped rather than allowed to undo a switch that happened.

The user-data template is rendered by the state machine rather than baked in,
so the commit reaches the instance without a Lambda in the path.
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

# An instance has to be `running` before it can be registered, and it is still
# `pending` moments after launch. Both spellings, because the error name the
# service integration reports is the SDK's and the API reference's differs.
_NOT_YET_RUNNING_RETRY = {
    "ErrorEquals": [
        "ElasticLoadBalancingV2.InvalidTargetException",
        "ElasticLoadBalancingV2.InvalidTarget",
    ],
    "IntervalSeconds": 10,
    "MaxAttempts": 30,
    "BackoffRate": 1.0,
}

_ABORT = [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure", "Next": "Abort"}]
"""Before the switch: any failure unwinds."""

NEVER_HEALTHY = {"Error": "NeverHealthy", "Cause": "the new instance never passed its health check"}


def _tidy(next_state: str) -> list:
    """After the switch: a failure is noted and the next thing is tried."""
    return [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.tidyError", "Next": next_state}]


def build_definition(
    *,
    app_repo: str,
    domain: str,
    image_id: str,
    instance_type: str,
    subnet_id: str,
    security_group_id: str,
    vpc_id: str,
    instance_profile: str,
    name_tag: str,
    resource_prefix: str,
    listener_arn: str,
    app_port: int,
    health_path: str,
    health_interval: int,
    health_timeout: int,
    healthy_threshold: int,
    unhealthy_threshold: int,
    healthy_poll_interval: int,
    healthy_poll_attempts: int,
    drain_seconds: int,
    dashboard_bucket: str,
    current_param: str,
    pending_param: str,
    fallback_status_code: int,
    fallback_body: str,
) -> dict:
    """A Standard definition: launch, wait for healthy, switch, retire, record.

    Input is `{commit, at, immediate}` — `at` being when the apply was received,
    which names its record; `immediate` is carried for the record and nothing
    else.
    """
    # PLACEHOLDER marks where the commit is substituted; everything else is
    # literal text that escape_for_format has to protect.
    #
    # The domain is the whole of what an application is handed, because it is the
    # whole of what an application cannot work out for itself. A region would say
    # enclavize can be pointed at more than one, and it cannot; the commit is
    # already what the repo was checked out at; and which port and path to
    # answer on are the contract, written down rather than passed in.
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
    group_name = f"States.Format('{escape_for_format(naming.target_group_name(resource_prefix, PLACEHOLDER))}', $.runId)"
    fallback = {
        "Type": "fixed-response",
        "FixedResponseConfig": {
            "StatusCode": str(fallback_status_code),
            "ContentType": "text/plain",
            "MessageBody": fallback_body,
        },
    }

    def record(key_path: str, body: dict, next_state: str, catch: list) -> dict:
        return {
            "Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
            "Parameters": {
                "Bucket": dashboard_bucket,
                "Key.$": key_path,
                "ContentType": "application/json",
                "CacheControl": naming.CHANGES_CACHE_CONTROL,
                "Body": body,
            },
            "ResultPath": None,
            "Catch": catch,
            "Next": next_state,
        }

    return {
        "Comment": "enclavize: put one commit behind the load balancer and retire the last",
        "StartAt": "Begin",
        "States": {
            "Begin": {
                "Type": "Pass",
                "Parameters": {
                    "commit.$": "$.commit",
                    "at.$": "$.at",
                    "immediate.$": "$.immediate",
                    # Names this attempt's target group: the same commit can be
                    # applied twice, and the first's group may still be live.
                    "runId.$": "States.ArrayGetItem(States.StringSplit(States.UUID(), '-'), 0)",
                    "recordKey.$": (
                        f"States.Format('{naming.APPLIES_PREFIX}{{}}_{{}}.json', $.at, $.commit)"
                    ),
                    "userData.$": (
                        f"States.Base64Encode(States.Format('{escape_for_format(user_data_template)}', "
                        "$.commit))"
                    ),
                    "counter": {"n": 0},
                },
                "Next": "RecordSwitching",
            },
            # A scheduled apply sat in the record as "scheduled" until now; the
            # dashboard should say the switch is under way the moment it is.
            # Nothing has been built yet, so failing to say so is not worth
            # stopping for.
            "RecordSwitching": record(
                "$.recordKey",
                {
                    "commit.$": "$.commit",
                    "startedAt.$": "$.at",
                    "switchAt.$": "$$.State.EnteredTime",
                    "status": "switching",
                },
                "ReadCurrent",
                _tidy("ReadCurrent"),
            ),
            "ReadCurrent": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:getParameter",
                "Parameters": {"Name": current_param},
                "ResultSelector": {"parsed.$": "States.StringToJson($.Parameter.Value)"},
                "ResultPath": "$.previous",
                "Catch": [
                    {
                        "ErrorEquals": ["Ssm.ParameterNotFoundException"],
                        "ResultPath": "$.noPrevious",
                        "Next": "CreateTargetGroup",
                    }
                ],
                "Next": "CreateTargetGroup",
            },
            "CreateTargetGroup": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:createTargetGroup",
                "Parameters": {
                    "Name.$": group_name,
                    "Protocol": "HTTP",
                    "Port": app_port,
                    "VpcId": vpc_id,
                    "TargetType": "instance",
                    "HealthCheckProtocol": "HTTP",
                    "HealthCheckPath": health_path,
                    "HealthCheckIntervalSeconds": health_interval,
                    "HealthCheckTimeoutSeconds": health_timeout,
                    "HealthyThresholdCount": healthy_threshold,
                    "UnhealthyThresholdCount": unhealthy_threshold,
                    "Matcher": {"HttpCode": "200"},
                    "Tags": [{"Key": "Name", "Value.$": group_name}],
                },
                "ResultSelector": {"arn.$": "$.TargetGroups[0].TargetGroupArn"},
                "ResultPath": "$.group",
                # Nothing made yet, so nothing to unwind.
                "Catch": [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure",
                           "Next": "ClearPendingAfterAbort"}],
                "Next": "SetDrain",
            },
            "SetDrain": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:modifyTargetGroupAttributes",
                "Parameters": {
                    "TargetGroupArn.$": "$.group.arn",
                    "Attributes": [
                        {"Key": "deregistration_delay.timeout_seconds", "Value": str(drain_seconds)}
                    ],
                },
                "ResultPath": None,
                "Catch": _ABORT,
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
                    # The group that admits the load balancer and nothing else.
                    "SecurityGroupIds": [security_group_id],
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
                "ResultSelector": {"instanceId.$": "$.Instances[0].InstanceId"},
                "ResultPath": "$.launch",
                "Catch": _ABORT,
                "Next": "RegisterTarget",
            },
            "RegisterTarget": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:registerTargets",
                "Parameters": {
                    "TargetGroupArn.$": "$.group.arn",
                    "Targets": [{"Id.$": "$.launch.instanceId"}],
                },
                "Retry": [_NOT_YET_RUNNING_RETRY],
                "ResultPath": None,
                "Catch": _ABORT,
                "Next": "AttachHow?",
            },
            # On the listener at weight zero: checked, and given no traffic.
            # The first version has nothing to sit beside, so it goes on alone
            # — there is no service yet for its warm-up to interrupt.
            "AttachHow?": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.previous.parsed", "IsPresent": True, "Next": "AttachBesideOld"},
                ],
                "Default": "AttachAlone",
            },
            "AttachBesideOld": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:modifyListener",
                "Parameters": {
                    "ListenerArn": listener_arn,
                    "DefaultActions": [
                        {
                            "Type": "forward",
                            "ForwardConfig": {
                                "TargetGroups": [
                                    {"TargetGroupArn.$": "$.previous.parsed.targetGroupArn",
                                     "Weight": 100},
                                    {"TargetGroupArn.$": "$.group.arn", "Weight": 0},
                                ]
                            },
                        }
                    ],
                },
                "ResultPath": "$.attached",
                "Catch": _ABORT,
                "Next": "CheckHealth",
            },
            "AttachAlone": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:modifyListener",
                "Parameters": {
                    "ListenerArn": listener_arn,
                    "DefaultActions": [{"Type": "forward", "TargetGroupArn.$": "$.group.arn"}],
                },
                "ResultPath": "$.attached",
                "Catch": _ABORT,
                "Next": "CheckHealth",
            },
            "CheckHealth": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:describeTargetHealth",
                "Parameters": {
                    "TargetGroupArn.$": "$.group.arn",
                    "Targets": [{"Id.$": "$.launch.instanceId"}],
                },
                "ResultSelector": {"state.$": "$.TargetHealthDescriptions[0].TargetHealth.State"},
                "ResultPath": "$.health",
                "Catch": _ABORT,
                "Next": "Healthy?",
            },
            "Healthy?": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.health.state", "StringEquals": "healthy",
                     "Next": "SwitchListener"},
                    {"Variable": "$.counter.n", "NumericGreaterThanEquals": healthy_poll_attempts,
                     "Next": "GaveUp"},
                ],
                "Default": "WaitForHealth",
            },
            "WaitForHealth": {
                "Type": "Wait",
                "Seconds": healthy_poll_interval,
                "Next": "CountAttempt",
            },
            "CountAttempt": {
                "Type": "Pass",
                "Parameters": {"n.$": "States.MathAdd($.counter.n, 1)"},
                "ResultPath": "$.counter",
                "Next": "CheckHealth",
            },
            "GaveUp": {
                "Type": "Pass",
                "Result": NEVER_HEALTHY,
                "ResultPath": "$.failure",
                "Next": "Abort",
            },
            # The switch. New connections go to the new version from here on;
            # the old group leaves the rule and drains.
            "SwitchListener": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:modifyListener",
                "Parameters": {
                    "ListenerArn": listener_arn,
                    "DefaultActions": [{"Type": "forward", "TargetGroupArn.$": "$.group.arn"}],
                },
                "ResultPath": None,
                "Catch": _ABORT,
                "Next": "DescribeCurrent",
            },
            # --- past here the switch has happened and nothing unwinds it ---
            "DescribeCurrent": {
                "Type": "Pass",
                "Parameters": {
                    "commit.$": "$.commit",
                    "instanceId.$": "$.launch.instanceId",
                    "targetGroupArn.$": "$.group.arn",
                    "since.$": "$$.State.EnteredTime",
                    "startedAt.$": "$.at",
                    # So the switch that retires this version can find its record.
                    "recordKey.$": "$.recordKey",
                },
                "ResultPath": "$.current",
                "Next": "WriteCurrent",
            },
            "WriteCurrent": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:putParameter",
                "Parameters": {
                    "Name": current_param,
                    "Value.$": "States.JsonToString($.current)",
                    "Type": "String",
                    "Overwrite": True,
                },
                "Retry": [{"ErrorEquals": ["States.ALL"], "IntervalSeconds": 5, "MaxAttempts": 3}],
                "ResultPath": None,
                "Catch": _tidy("HadPrevious?"),
                "Next": "HadPrevious?",
            },
            "HadPrevious?": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.previous.parsed", "IsPresent": True, "Next": "DeregisterOld"},
                ],
                "Default": "ClearPending",
            },
            "DeregisterOld": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:deregisterTargets",
                "Parameters": {
                    "TargetGroupArn.$": "$.previous.parsed.targetGroupArn",
                    "Targets": [{"Id.$": "$.previous.parsed.instanceId"}],
                },
                "ResultPath": None,
                "Catch": _tidy("Drain"),
                "Next": "Drain",
            },
            # The requests it was holding when the switch happened.
            "Drain": {
                "Type": "Wait",
                "Seconds": drain_seconds,
                "Next": "TerminateOld",
            },
            "TerminateOld": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ec2:terminateInstances",
                "Parameters": {"InstanceIds.$": "States.Array($.previous.parsed.instanceId)"},
                "ResultPath": None,
                "Catch": _tidy("DeleteOldGroup"),
                "Next": "DeleteOldGroup",
            },
            "DeleteOldGroup": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:deleteTargetGroup",
                "Parameters": {"TargetGroupArn.$": "$.previous.parsed.targetGroupArn"},
                "ResultPath": None,
                "Catch": _tidy("RetireOldRecord"),
                "Next": "RetireOldRecord",
            },
            "RetireOldRecord": record(
                "$.previous.parsed.recordKey",
                {
                    "commit.$": "$.previous.parsed.commit",
                    "instanceId.$": "$.previous.parsed.instanceId",
                    "startedAt.$": "$.previous.parsed.startedAt",
                    "switchedAt.$": "$.previous.parsed.since",
                    "retiredAt.$": "$.current.since",
                    "status": "retired",
                },
                "ClearPending",
                _tidy("ClearPending"),
            ),
            "ClearPending": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:deleteParameter",
                "Parameters": {"Name": pending_param},
                "ResultPath": None,
                "Catch": _tidy("UpdateRecord"),
                "Next": "UpdateRecord",
            },
            "UpdateRecord": record(
                "$.recordKey",
                {
                    "commit.$": "$.commit",
                    "instanceId.$": "$.launch.instanceId",
                    "startedAt.$": "$.at",
                    "switchedAt.$": "$.current.since",
                    "status": "live",
                },
                "Done",
                _tidy("Done"),
            ),
            "Done": {"Type": "Succeed"},
            # --- unwinding: whatever was made, in reverse ------------------
            "Abort": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.attached", "IsPresent": True, "Next": "DetachHow?"},
                ],
                "Default": "TerminateNew?",
            },
            "DetachHow?": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.previous.parsed", "IsPresent": True, "Next": "RestoreOld"},
                ],
                "Default": "RestoreFallback",
            },
            "RestoreOld": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:modifyListener",
                "Parameters": {
                    "ListenerArn": listener_arn,
                    "DefaultActions": [
                        {"Type": "forward", "TargetGroupArn.$": "$.previous.parsed.targetGroupArn"}
                    ],
                },
                "ResultPath": None,
                "Catch": _tidy("TerminateNew?"),
                "Next": "TerminateNew?",
            },
            "RestoreFallback": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:modifyListener",
                "Parameters": {"ListenerArn": listener_arn, "DefaultActions": [fallback]},
                "ResultPath": None,
                "Catch": _tidy("TerminateNew?"),
                "Next": "TerminateNew?",
            },
            "TerminateNew?": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.launch.instanceId", "IsPresent": True, "Next": "TerminateNew"},
                ],
                "Default": "DeleteNewGroup",
            },
            "TerminateNew": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ec2:terminateInstances",
                "Parameters": {"InstanceIds.$": "States.Array($.launch.instanceId)"},
                "ResultPath": None,
                "Catch": _tidy("DeleteNewGroup"),
                "Next": "DeleteNewGroup",
            },
            "DeleteNewGroup": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:elasticloadbalancingv2:deleteTargetGroup",
                "Parameters": {"TargetGroupArn.$": "$.group.arn"},
                "ResultPath": None,
                "Catch": _tidy("ClearPendingAfterAbort"),
                "Next": "ClearPendingAfterAbort",
            },
            "ClearPendingAfterAbort": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:ssm:deleteParameter",
                "Parameters": {"Name": pending_param},
                "ResultPath": None,
                "Catch": _tidy("RecordFailed"),
                "Next": "RecordFailed",
            },
            "RecordFailed": record(
                "$.recordKey",
                {
                    "commit.$": "$.commit",
                    "startedAt.$": "$.at",
                    "failedAt.$": "$$.State.EnteredTime",
                    "status": "failed",
                },
                "Failed",
                _tidy("Failed"),
            ),
            "Failed": {
                "Type": "Fail",
                "ErrorPath": "$.failure.Error",
                "CausePath": "$.failure.Cause",
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
