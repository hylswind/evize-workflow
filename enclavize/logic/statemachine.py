"""The apply state machine's definition, as data.

It does one thing: launch an instance that will clone the app and run it. It
deliberately does not wait for the commit to finish applying — an Express workflow tops
out at five minutes and API Gateway's integration at 29 seconds, while a real
apply takes longer than both. Progress is watched on the dashboard instead.

The user-data template is rendered by the state machine rather than baked in,
so the commit reaches the instance without a Lambda in the path.
"""

# Instance-profile propagation reaches this launch too, so the state machine
# retries it the same way the sealing launch does.
_PROFILE_RETRY = {
    "ErrorEquals": ["Ec2.Ec2Exception", "States.TaskFailed"],
    "IntervalSeconds": 3,
    "MaxAttempts": 20,
    "BackoffRate": 1.0,
}


def build_definition(
    *,
    app_repo: str,
    region: str,
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
            f"export AWS_DEFAULT_REGION={region}",
            f"export ENCLAVIZE_REGION={region}",
            f"export ENCLAVIZE_DOMAIN={domain}",
            f"export ENCLAVIZE_COMMIT={PLACEHOLDER}",
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
                    "userData.$": (
                        f"States.Base64Encode(States.Format('{escape_for_format(user_data_template)}', "
                        "$.commit, $.commit))"
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
            "RecordApply": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Parameters": {
                    "Bucket": dashboard_bucket,
                    "Key.$": "States.Format('applies/{}.json', $.commit)",
                    "ContentType": "application/json",
                    "Body": {
                        "commit.$": "$.commit",
                        "instanceId.$": "$.launch.Instances[0].InstanceId",
                        "startedAt.$": "$$.State.EnteredTime",
                    },
                },
                "ResultPath": None,
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
