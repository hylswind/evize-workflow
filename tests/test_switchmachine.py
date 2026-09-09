"""The switching state machine's definition.

What is pinned here is the order that makes the switch safe: the new version
is health-checked before it gets traffic, traffic moves in one change and only
once the balancer has said healthy, the old version goes only after the new
one is in, and anything that fails first unwinds without touching what was
serving.

The escaping rules come from the Amazon States Language spec: ' { } and \\
are reserved inside an intrinsic invocation and each must be preceded by a
backslash.
"""

import json

from constants import APP_REPO, DOMAIN

from enclavize.logic import naming
from enclavize.logic import switchmachine as sw
from setup import config as setup_config

DASHBOARD_BUCKET = "enclavize-dashboard-123456789012"
LISTENER = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/enclavize-app/l1/l2"
CURRENT = "/enclavize/apply/current"
PENDING = "/enclavize/apply/pending"
ATTEMPTS = 240


def definition(**overrides):
    kwargs = dict(
        app_repo=APP_REPO,
        domain=DOMAIN,
        image_id="ami-1",
        instance_type=setup_config.APPLY_INSTANCE_TYPE,
        subnet_id="subnet-1",
        security_group_id="sg-app",
        vpc_id="vpc-1",
        instance_profile="enclavize-apply",
        name_tag="enclavize-apply",
        resource_prefix="enclavize-",
        listener_arn=LISTENER,
        app_port=80,
        health_path="/healthz",
        health_interval=10,
        health_timeout=5,
        healthy_threshold=2,
        unhealthy_threshold=2,
        healthy_poll_interval=15,
        healthy_poll_attempts=ATTEMPTS,
        drain_seconds=30,
        dashboard_bucket=DASHBOARD_BUCKET,
        current_param=CURRENT,
        pending_param=PENDING,
        fallback_status_code=503,
        fallback_body="no version applied yet",
    )
    kwargs.update(overrides)
    return sw.build_definition(**kwargs)


def states():
    return definition()["States"]


def user_data_expression():
    return states()["Begin"]["Parameters"]["userData.$"]


def successors(state):
    out = [state[k] for k in ("Next", "Default") if k in state]
    out += [c["Next"] for c in state.get("Choices", [])]
    out += [c["Next"] for c in state.get("Catch", [])]
    return out


def reachable(start, without=None):
    """Every state reachable from `start`; `without` cuts one state's exits."""
    seen, stack = set(), [start]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        if name != without:
            stack.extend(successors(states()[name]))
    return seen


# --- escaping -------------------------------------------------------------


def test_reserved_characters_are_escaped():
    assert sw.escape_for_format("a'b") == "a\\'b"
    assert sw.escape_for_format("a{b") == "a\\{b"
    assert sw.escape_for_format("a}b") == "a\\}b"
    assert sw.escape_for_format("a\\b") == "a\\\\b"


def test_placeholders_survive_escaping():
    # Braces in the script get escaped; the substitution slots must not.
    rendered = sw.escape_for_format(f"echo ${{HOME}} {sw.PLACEHOLDER}")
    assert rendered == "echo $\\{HOME\\} {}"


def test_a_backslash_is_escaped_before_anything_else():
    # Otherwise the backslash added for a quote would itself be doubled.
    assert sw.escape_for_format("\\'") == "\\\\\\'"


# --- what the instance is handed ------------------------------------------


def test_the_commit_is_substituted_where_the_script_needs_it():
    expression = user_data_expression()
    # Once, to check the repo out. The app is not handed the commit separately:
    # it is already sitting at it.
    assert expression.count("{}") == 1
    assert expression.endswith("$.commit))")


def test_the_user_data_is_base64_encoded_because_run_instances_expects_that():
    assert user_data_expression().startswith("States.Base64Encode(States.Format(")


def test_the_script_clones_the_app_repo_and_runs_its_entrypoint():
    expression = user_data_expression()
    assert f"git clone https://github.com/{APP_REPO}.git /opt/app" in expression
    assert "exec ./setup.sh" in expression


def test_the_script_fails_fast():
    assert "#!/bin/bash\nset -euxo pipefail" in user_data_expression()


def test_an_apply_instance_does_not_carry_the_api_key():
    """It has no business holding the key that triggers applies: a commit that
    could read it could apply another one."""
    assert "APPLY_API_KEY" not in user_data_expression()


def test_the_script_stops_tracing_before_exporting_anything():
    expression = user_data_expression()
    assert expression.index("set +x") < expression.index("export ENCLAVIZE_DOMAIN")


def test_the_domain_is_all_an_application_is_handed():
    """The contract the README states, pinned here. A region would advertise
    something enclavize cannot vary; the commit is already what the repo was
    checked out at; and the port and path to answer on are the contract,
    written down rather than passed in."""
    exported = [line for line in user_data_expression().splitlines()
                if line.startswith("export ")]
    assert exported == [f"export ENCLAVIZE_DOMAIN={DOMAIN}"]


# --- launching ------------------------------------------------------------


def test_it_launches_with_the_bounded_apply_profile_behind_the_front_door():
    launch = states()["LaunchInstance"]
    assert launch["Resource"] == "arn:aws:states:::aws-sdk:ec2:runInstances"
    assert launch["Parameters"]["IamInstanceProfile"] == {"Name": "enclavize-apply"}
    assert launch["Parameters"]["UserData.$"] == "$.userData"
    # The group that admits the load balancer and nothing else.
    assert launch["Parameters"]["SecurityGroupIds"] == ["sg-app"]
    tags = launch["Parameters"]["TagSpecifications"][0]["Tags"]
    assert {"Key": "Name", "Value": "enclavize-apply"} in tags


def test_launching_retries_while_the_instance_profile_propagates():
    retry = states()["LaunchInstance"]["Retry"][0]
    assert retry["MaxAttempts"] >= 10
    assert retry["IntervalSeconds"] <= 5


def test_registration_waits_for_the_instance_to_be_running():
    """An instance must be `running` to register, and it is still `pending`
    moments after launch. Retried rather than waited for: the error is the
    signal."""
    retry = states()["RegisterTarget"]["Retry"][0]
    assert "ElasticLoadBalancingV2.InvalidTargetException" in retry["ErrorEquals"]
    assert retry["MaxAttempts"] * retry["IntervalSeconds"] >= 120


# --- the target group ------------------------------------------------------


def test_each_switch_gets_its_own_target_group():
    """The same commit can be applied twice, and the first's group may still be
    live — so the name is per attempt, and matches the helper the teardown
    finds them with."""
    begin = states()["Begin"]["Parameters"]
    assert begin["runId.$"] == "States.ArrayGetItem(States.StringSplit(States.UUID(), '-'), 0)"
    expression = states()["CreateTargetGroup"]["Parameters"]["Name.$"]
    template = expression.split("'")[1]
    assert template.format("RUN") == naming.target_group_name("enclavize-", "RUN")
    assert len(template.format("0123abcd")) <= 32


def test_the_health_check_is_the_contract_the_readme_states():
    group = states()["CreateTargetGroup"]
    assert group["Resource"] == "arn:aws:states:::aws-sdk:elasticloadbalancingv2:createTargetGroup"
    parameters = group["Parameters"]
    assert parameters["Protocol"] == "HTTP"
    assert parameters["Port"] == 80
    assert parameters["TargetType"] == "instance"
    assert parameters["VpcId"] == "vpc-1"
    assert parameters["HealthCheckPath"] == "/healthz"
    assert parameters["HealthCheckIntervalSeconds"] == 10
    assert parameters["HealthCheckTimeoutSeconds"] == 5
    assert parameters["HealthyThresholdCount"] == 2
    assert parameters["UnhealthyThresholdCount"] == 2
    assert parameters["Matcher"] == {"HttpCode": "200"}


def test_the_retiring_instance_is_given_time_to_drain():
    drain = states()["SetDrain"]["Parameters"]["Attributes"]
    assert drain == [{"Key": "deregistration_delay.timeout_seconds", "Value": "30"}]
    assert states()["Drain"] == {"Type": "Wait", "Seconds": 30, "Next": "TerminateOld"}


# --- the switch ------------------------------------------------------------


def test_the_new_version_is_checked_before_it_gets_any_traffic():
    """The balancer checks only the groups a listener names, so the new group
    goes on the listener at weight zero: checked, and given nothing."""
    attach = states()["AttachBesideOld"]
    assert attach["Resource"] == "arn:aws:states:::aws-sdk:elasticloadbalancingv2:modifyListener"
    assert attach["Parameters"]["ListenerArn"] == LISTENER
    groups = attach["Parameters"]["DefaultActions"][0]["ForwardConfig"]["TargetGroups"]
    assert groups == [
        {"TargetGroupArn.$": "$.previous.parsed.targetGroupArn", "Weight": 100},
        {"TargetGroupArn.$": "$.group.arn", "Weight": 0},
    ]
    assert states()["AttachHow?"]["Choices"][0]["Next"] == "AttachBesideOld"
    assert states()["AttachHow?"]["Default"] == "AttachAlone"
    assert attach["Next"] == "CheckHealth"


def test_the_first_version_goes_on_alone():
    # There is no service yet for its warm-up to interrupt.
    alone = states()["AttachAlone"]
    assert alone["Parameters"]["DefaultActions"] == [
        {"Type": "forward", "TargetGroupArn.$": "$.group.arn"}
    ]


def test_traffic_moves_only_from_the_branch_that_saw_healthy():
    """The balancer would not stop it moving earlier: a group whose only target
    is unhealthy is sent traffic anyway."""
    healthy = states()["Healthy?"]
    to_switch = [c for c in healthy["Choices"] if c["Next"] == "SwitchListener"]
    assert to_switch == [{"Variable": "$.health.state", "StringEquals": "healthy",
                          "Next": "SwitchListener"}]
    # Nothing else leads there.
    entering = [name for name, s in states().items() if "SwitchListener" in successors(s)]
    assert entering == ["Healthy?"]

    switch = states()["SwitchListener"]
    assert switch["Parameters"]["DefaultActions"] == [
        {"Type": "forward", "TargetGroupArn.$": "$.group.arn"}
    ]


def test_the_health_check_asks_the_balancer_rather_than_the_instance():
    check = states()["CheckHealth"]
    assert check["Resource"] == "arn:aws:states:::aws-sdk:elasticloadbalancingv2:describeTargetHealth"
    assert check["Parameters"]["Targets"] == [{"Id.$": "$.launch.instanceId"}]
    assert check["ResultSelector"] == {"state.$": "$.TargetHealthDescriptions[0].TargetHealth.State"}


def test_waiting_for_healthy_is_bounded():
    healthy = states()["Healthy?"]
    assert healthy["Default"] == "WaitForHealth"
    assert states()["WaitForHealth"] == {"Type": "Wait", "Seconds": 15, "Next": "CountAttempt"}
    assert states()["CountAttempt"]["Parameters"] == {"n.$": "States.MathAdd($.counter.n, 1)"}
    assert states()["CountAttempt"]["Next"] == "CheckHealth"
    gave_up = [c for c in healthy["Choices"] if c["Next"] == "GaveUp"]
    assert gave_up == [{"Variable": "$.counter.n", "NumericGreaterThanEquals": ATTEMPTS,
                        "Next": "GaveUp"}]
    assert states()["Begin"]["Parameters"]["counter"] == {"n": 0}


# --- after the switch ------------------------------------------------------


def test_the_account_records_what_is_serving():
    current = states()["DescribeCurrent"]["Parameters"]
    assert set(current) == {"commit.$", "instanceId.$", "targetGroupArn.$", "since.$",
                            "startedAt.$", "recordKey.$"}
    write = states()["WriteCurrent"]
    assert write["Parameters"]["Name"] == CURRENT
    assert write["Parameters"]["Value.$"] == "States.JsonToString($.current)"
    assert write["Parameters"]["Overwrite"] is True


def test_the_old_version_goes_only_after_the_new_one_is_recorded():
    # Cut WriteCurrent's exits and nothing can reach the retirement.
    assert "TerminateOld" in reachable("Begin")
    assert "TerminateOld" not in reachable("Begin", without="WriteCurrent")
    assert "TerminateOld" not in reachable("Begin", without="SwitchListener")


def test_the_old_version_is_deregistered_drained_terminated_and_deleted():
    assert states()["DeregisterOld"]["Next"] == "Drain"
    assert states()["Drain"]["Next"] == "TerminateOld"
    assert states()["TerminateOld"]["Parameters"] == {
        "InstanceIds.$": "States.Array($.previous.parsed.instanceId)"
    }
    assert states()["TerminateOld"]["Next"] == "DeleteOldGroup"
    assert states()["DeleteOldGroup"]["Parameters"] == {
        "TargetGroupArn.$": "$.previous.parsed.targetGroupArn"
    }


def test_nothing_after_the_switch_can_unwind_it():
    """Tidying is skipped rather than allowed to undo a switch that happened."""
    after = reachable("DescribeCurrent")
    assert not after & {"Abort", "RestoreOld", "RestoreFallback", "TerminateNew", "DeleteNewGroup"}
    for name in after:
        for catch in states()[name].get("Catch", []):
            assert catch["Next"] in after, name


def test_every_way_out_clears_pending():
    assert "Done" not in reachable("Begin", without="ClearPending")
    assert "Failed" not in reachable("Begin", without="ClearPendingAfterAbort")
    for name in ("ClearPending", "ClearPendingAfterAbort"):
        assert states()[name]["Parameters"] == {"Name": PENDING}


def test_the_records_say_what_became_of_each_version():
    live = states()["UpdateRecord"]["Parameters"]
    assert live["Key.$"] == "$.recordKey"
    assert live["Body"]["status"] == "live"
    retired = states()["RetireOldRecord"]["Parameters"]
    assert retired["Key.$"] == "$.previous.parsed.recordKey"
    assert retired["Body"]["status"] == "retired"
    failed = states()["RecordFailed"]["Parameters"]
    assert failed["Key.$"] == "$.recordKey"
    assert failed["Body"]["status"] == "failed"
    for record in (live, retired, failed):
        assert record["CacheControl"] == naming.CHANGES_CACHE_CONTROL


# --- unwinding -------------------------------------------------------------


def test_a_failure_before_the_switch_unwinds():
    for name in ("SetDrain", "LaunchInstance", "RegisterTarget", "AttachBesideOld",
                 "AttachAlone", "CheckHealth", "SwitchListener"):
        catch = states()[name]["Catch"][0]
        assert catch["ErrorEquals"] == ["States.ALL"], name
        assert catch["Next"] == "Abort", name
        assert catch["ResultPath"] == "$.failure", name
    # Nothing made yet, so nothing to unwind.
    assert states()["CreateTargetGroup"]["Catch"][0]["Next"] == "ClearPendingAfterAbort"


def test_unwinding_takes_the_new_version_off_the_listener_first():
    """Detached before it is terminated, so the listener never forwards to a
    group whose only instance is going."""
    assert states()["Abort"]["Choices"][0] == {"Variable": "$.attached", "IsPresent": True,
                                               "Next": "DetachHow?"}
    restore = states()["RestoreOld"]["Parameters"]["DefaultActions"]
    assert restore == [{"Type": "forward", "TargetGroupArn.$": "$.previous.parsed.targetGroupArn"}]
    fallback = states()["RestoreFallback"]["Parameters"]["DefaultActions"][0]
    assert fallback["Type"] == "fixed-response"
    assert fallback["FixedResponseConfig"]["StatusCode"] == "503"
    unwound = reachable("Abort")
    assert {"TerminateNew", "DeleteNewGroup", "ClearPendingAfterAbort", "RecordFailed", "Failed"} <= unwound
    assert states()["TerminateNew"]["Parameters"] == {
        "InstanceIds.$": "States.Array($.launch.instanceId)"
    }


def test_giving_up_says_why():
    assert states()["GaveUp"]["Result"] == sw.NEVER_HEALTHY
    assert states()["GaveUp"]["ResultPath"] == "$.failure"
    failed = states()["Failed"]
    assert failed["Type"] == "Fail"
    assert failed["ErrorPath"] == "$.failure.Error"
    assert failed["CausePath"] == "$.failure.Cause"


# --- shape -----------------------------------------------------------------


def test_the_time_of_the_switch_is_stamped_where_it_happens():
    stamped = [name for name, s in states().items() if "$$.State.EnteredTime" in json.dumps(s)]
    assert stamped == ["DescribeCurrent", "RecordFailed"]


def test_every_transition_resolves():
    for name, state in states().items():
        for target in successors(state):
            assert target in states(), (name, target)


def test_the_definition_serialises():
    assert json.loads(json.dumps(definition()))["StartAt"] == "Begin"
