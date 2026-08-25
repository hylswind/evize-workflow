"""The deploy state machine definition.

The escaping rules here come from the Amazon States Language spec: ' { } and \\
are reserved inside an intrinsic invocation and each must be preceded by a
backslash.
"""

import json

from constants import APP_REPO, DOMAIN, REGION

from enclavize.logic import statemachine as sm

DASHBOARD_BUCKET = "enclavize-dashboard-123456789012"


def definition():
    return sm.build_definition(
        app_repo=APP_REPO,
        region=REGION,
        domain=DOMAIN,
        image_id="ami-1",
        instance_type="t3.small",
        subnet_id="subnet-1",
        instance_profile="enclavize-deploy",
        dashboard_bucket=DASHBOARD_BUCKET,
        name_tag="enclavize-deploy",
    )


def user_data_expression():
    return definition()["States"]["RenderUserData"]["Parameters"]["userData.$"]


# --- escaping -------------------------------------------------------------


def test_reserved_characters_are_escaped():
    assert sm.escape_for_format("a'b") == "a\\'b"
    assert sm.escape_for_format("a{b") == "a\\{b"
    assert sm.escape_for_format("a}b") == "a\\}b"
    assert sm.escape_for_format("a\\b") == "a\\\\b"


def test_placeholders_survive_escaping():
    # Braces in the script get escaped; the substitution slots must not.
    rendered = sm.escape_for_format(f"echo ${{HOME}} {sm.PLACEHOLDER}")
    assert rendered == "echo $\\{HOME\\} {}"


def test_a_backslash_is_escaped_before_anything_else():
    # Otherwise the backslash added for a quote would itself be doubled.
    assert sm.escape_for_format("\\'") == "\\\\\\'"


# --- what the workflow does ----------------------------------------------


def test_the_commit_is_substituted_where_the_script_needs_it():
    expression = user_data_expression()
    # Once to check out, once to export for the app.
    assert expression.count("{}") == 2
    assert expression.endswith("$.commit, $.commit))")


def test_the_user_data_is_base64_encoded_because_run_instances_expects_that():
    assert user_data_expression().startswith("States.Base64Encode(States.Format(")


def test_the_script_clones_the_app_repo_and_runs_its_entrypoint():
    expression = user_data_expression()
    assert f"git clone https://github.com/{APP_REPO}.git /opt/app" in expression
    assert "exec ./setup.sh" in expression


def test_the_script_stops_tracing_before_exporting_anything():
    expression = user_data_expression()
    assert expression.index("set +x") < expression.index("export ENCLAVIZE_COMMIT")


def test_it_launches_with_the_bounded_deploy_profile():
    launch = definition()["States"]["LaunchInstance"]
    assert launch["Resource"] == "arn:aws:states:::aws-sdk:ec2:runInstances"
    assert launch["Parameters"]["IamInstanceProfile"] == {"Name": "enclavize-deploy"}
    assert launch["Parameters"]["UserData.$"] == "$.userData"


def test_launching_retries_while_the_instance_profile_propagates():
    # The same delay that the sealing launch has to absorb.
    retry = definition()["States"]["LaunchInstance"]["Retry"][0]
    assert retry["MaxAttempts"] >= 10
    assert retry["IntervalSeconds"] <= 5


def test_every_deploy_is_recorded_for_the_dashboard():
    record = definition()["States"]["RecordDeploy"]
    assert record["Resource"] == "arn:aws:states:::aws-sdk:s3:putObject"
    assert record["Parameters"]["Bucket"] == DASHBOARD_BUCKET
    assert record["Parameters"]["Key.$"] == "States.Format('deploys/{}.json', $.commit)"
    assert record["Parameters"]["Body"]["instanceId.$"] == "$.launch.Instances[0].InstanceId"


def test_it_returns_as_soon_as_the_instance_exists():
    """It must not wait for the deploy: Express tops out at five minutes and the
    API integration at 29 seconds."""
    done = definition()["States"]["Done"]
    assert done["End"] is True
    # "launched", not "deployed" — the instance has only just started.
    assert done["Parameters"]["status"] == "launched"
    assert done["Parameters"]["instanceId.$"] == "$.launch.Instances[0].InstanceId"


def test_no_state_waits_on_the_deploy_finishing():
    states = definition()["States"]
    assert not any(state["Type"] == "Wait" for state in states.values())
    # A .sync task would block until the work completed.
    assert not any(".sync" in str(state.get("Resource", "")) for state in states.values())


def test_the_definition_serialises():
    # It is sent as a JSON string, so anything unserialisable fails at create
    # time deep inside the bring-up.
    assert json.loads(json.dumps(definition()))["StartAt"] == "RenderUserData"
