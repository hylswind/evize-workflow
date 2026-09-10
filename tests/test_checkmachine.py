"""The checking state machine's definition.

What matters here is order and idempotence: nothing changes before the timer
is taken down, and a run that finds nothing to do touches nothing.
"""

import json

from constants import APP_REPO, DOMAIN

from enclavize.logic import checkmachine as cm
from enclavize.logic import naming
from setup import config as setup_config

DASHBOARD_BUCKET = "enclavize-dashboard-123456789012"
SCHEDULE = "enclavize-apply-check"
CURRENT, PENDING, READY = (f"/enclavize/apply/{w}" for w in ("current", "pending", "ready"))
TIMEOUT = 7 * 24 * 3600


def definition():
    return cm.build_definition(
        app_repo=APP_REPO,
        domain=DOMAIN,
        image_id="ami-1",
        instance_type=setup_config.APPLY_INSTANCE_TYPE,
        subnet_id="subnet-1",
        instance_profile="enclavize-apply",
        name_tag="enclavize-apply",
        dashboard_bucket=DASHBOARD_BUCKET,
        schedule_name=SCHEDULE,
        current_param=CURRENT,
        pending_param=PENDING,
        ready_param=READY,
        timeout_seconds=TIMEOUT,
    )


def states():
    return definition()["States"]


def walk(start, *, choose=None):
    seen = []
    name = start
    while name and name not in seen:
        seen.append(name)
        state = states()[name]
        if state["Type"] == "Choice":
            name = choose[name]
        else:
            name = state.get("Next")
    return seen


def writes(path):
    """The states on a path that change something."""
    reading = {"arn:aws:states:::aws-sdk:ssm:getParameter",
               "arn:aws:states:::aws-sdk:ec2:describeInstances"}
    return [n for n in path
            if states()[n]["Type"] == "Task" and states()[n]["Resource"] not in reading]


GO = {"Decide": "ClaimIt", "AnyPreparer?": "ClearReady"}


# --- the three answers ------------------------------------------------------


def test_nothing_pending_means_nothing_to_do():
    """A run that fired after the switch was done, or after an apply unwound."""
    read = states()["ReadPending"]
    assert read["Parameters"] == {"Name": PENDING}
    assert read["Catch"] == [{"ErrorEquals": ["Ssm.ParameterNotFoundException"],
                              "Next": "NothingInFlight"}]
    assert states()["NothingInFlight"] == {"Type": "Succeed"}


def test_no_word_yet_means_wait_for_the_next_look():
    path = walk("ReadPending", choose={"Decide": "NotYet"})
    assert path[-1] == "NotYet"
    assert writes(path) == []


def test_ready_counts_only_when_it_names_the_commit_that_is_pending():
    """A preparer that speaks late names the commit *it* was told about, not
    the one waiting now. Counted, it could let a later commit through before
    its own preparer had spoken."""
    decide = states()["Decide"]
    assert decide["QueryLanguage"] == "JSONata"
    go = decide["Choices"][0]
    assert go["Next"] == "ClaimIt"
    assert go["Condition"] == (
        "{% $exists($states.input.ready.Parameter.Value) and "
        "$states.input.ready.Parameter.Value = $states.input.pending.commit %}"
    )


def test_a_word_for_another_commit_is_cleared_and_then_waited_on():
    decide = states()["Decide"]
    stale = decide["Choices"][2]
    assert stale["Condition"] == "{% $exists($states.input.ready.Parameter.Value) %}"
    assert stale["Next"] == "ClearStaleReady"
    path = walk("ClearStaleReady")
    assert path == ["ClearStaleReady", "NotYet"]
    assert states()["ClearStaleReady"]["Parameters"] == {"Name": READY}


def test_the_wait_is_bounded_and_then_the_switch_goes_ahead():
    """Seven days, and then the timeout is treated the same as the word.
    Waiting is a courtesy to the serving version, not a veto."""
    decide = states()["Decide"]
    timeout = decide["Choices"][1]
    assert timeout["Next"] == "ClaimIt"
    assert timeout["Condition"] == (
        f"{{% $toMillis($states.input.pending.at) + {TIMEOUT * 1000} <= $toMillis($now()) %}}"
    )
    assert decide["Default"] == "NotYet"


def test_jsonata_is_confined_to_the_decision():
    speaking = {name for name, s in states().items() if s.get("QueryLanguage") == "JSONata"}
    assert speaking == {"Decide"}


# --- the lock ---------------------------------------------------------------


def test_taking_the_timer_down_is_the_first_side_effect_of_a_switch():
    """A delete is atomic: of two runs that both decided to switch, one gets
    NotFound and stops. Nothing before it changes anything, so the run that
    loses has nothing to undo."""
    path = walk("ReadPending", choose=GO)
    assert writes(path)[0] == "ClaimIt"
    claim = states()["ClaimIt"]
    assert claim["Resource"] == "arn:aws:states:::aws-sdk:scheduler:deleteSchedule"
    assert claim["Parameters"] == {"Name": SCHEDULE}
    assert claim["Catch"] == [{"ErrorEquals": ["Scheduler.ResourceNotFoundException"],
                               "Next": "AlreadyHandled"}]
    assert states()["AlreadyHandled"] == {"Type": "Succeed"}


def test_the_decision_is_read_from_the_parameters_not_from_the_input():
    """The timer starts this with an empty input, so everything comes from
    Parameter Store — and a run started by hand behaves the same way."""
    assert definition()["StartAt"] == "ReadPending"
    assert states()["ParsePending"]["Parameters"] == {
        "pending.$": "States.StringToJson($.pendingParam.Parameter.Value)",
    }
    assert states()["ReadReady"]["Parameters"] == {"Name": READY}


# --- the switch -------------------------------------------------------------


def test_a_preparer_still_running_is_stopped_before_the_new_commit_goes_in():
    """One that said ready has shut itself down already; one still running is
    one the timeout ran out on. Found by the tag that names what it was
    preparing for, so no other instance can be mistaken for it."""
    find = states()["FindPreparer"]
    assert find["Resource"] == "arn:aws:states:::aws-sdk:ec2:describeInstances"
    assert find["Parameters"]["Filters"] == [
        {"Name": f"tag:{naming.PREPARING_FOR_TAG}", "Values.$": "States.Array($.pending.commit)"},
        {"Name": "instance-state-name", "Values": ["pending", "running"]},
    ]
    stop = states()["StopPreparer"]
    assert stop["Resource"] == "arn:aws:states:::aws-sdk:ec2:terminateInstances"
    path = walk("ReadPending", choose={"Decide": "ClaimIt", "AnyPreparer?": "StopPreparer"})
    assert path.index("ClaimIt") < path.index("StopPreparer") < path.index("LaunchNew")


def test_the_new_commit_is_launched_as_new():
    """The version that serves, not a preparer: NEW mode, checked out at the
    pending commit, with no shutdown-terminates and no preparing-for tag."""
    user_data = states()["RenderNew"]["Parameters"]["userData.$"]
    assert "export ENCLAVIZE_MODE=NEW" in user_data
    assert "ENCLAVIZE_NEXT_COMMIT" not in user_data
    assert user_data.endswith("$.pending.commit))")
    launch = states()["LaunchNew"]
    assert launch["Parameters"]["IamInstanceProfile"] == {"Name": "enclavize-apply"}
    assert "InstanceInitiatedShutdownBehavior" not in launch["Parameters"]
    tags = {t["Key"] for t in launch["Parameters"]["TagSpecifications"][0]["Tags"]}
    assert tags == {"Name", naming.COMMIT_TAG}


def test_the_switch_always_writes_down_what_is_serving_before_it_tidies():
    path = walk("ReadPending", choose=GO)
    assert (path.index("LaunchNew") < path.index("WriteCurrent")
            < path.index("ClearPending") < path.index("RetireOldRecord")
            < path.index("UpdateRecord") < path.index("Done"))
    serving = states()["DescribeLaunched"]["Parameters"]
    assert serving == {
        "commit.$": "$.pending.commit",
        "instanceId.$": "$.launch.instanceId",
        "startedAt.$": "$.pending.at",
        "since.$": "$$.State.EnteredTime",
        "recordKey.$": "$.pending.recordKey",
    }
    write = states()["WriteCurrent"]
    assert write["Parameters"]["Name"] == CURRENT
    assert write["Parameters"]["Value.$"] == "States.JsonToString($.serving)"


def test_the_spent_word_is_cleared_on_the_way():
    path = walk("ReadPending", choose=GO)
    assert path.index("ClaimIt") < path.index("ClearReady") < path.index("LaunchNew")
    assert states()["ClearReady"]["Parameters"] == {"Name": READY}


def test_every_path_that_does_anything_clears_pending():
    """Pending standing is an apply in flight. Left behind after a switch or a
    failure it would refuse every later apply for good."""
    switched = walk("ReadPending", choose=GO)
    failed = walk("ClearPendingAfterFailure")
    assert "ClearPending" in switched
    assert failed[0] == "ClearPendingAfterFailure"
    for name in ("ClearPending", "ClearPendingAfterFailure"):
        assert states()[name]["Parameters"] == {"Name": PENDING}


def test_the_records_say_what_became_of_each_version():
    retire = states()["RetireOldRecord"]["Parameters"]
    assert retire["Key.$"] == "$.pending.previous.recordKey"
    assert retire["Body"]["status"] == "retired"
    assert retire["Body"]["replacedBy.$"] == "$.pending.commit"
    update = states()["UpdateRecord"]["Parameters"]
    assert update["Key.$"] == "$.pending.recordKey"
    assert update["Body"]["status"] == "launched"
    assert update["Body"]["instanceId.$"] == "$.serving.instanceId"
    assert update["Body"]["previous.$"] == "$.pending.previous.commit"
    for name in ("RetireOldRecord", "UpdateRecord", "RecordFailure"):
        assert states()[name]["Parameters"]["CacheControl"] == naming.CHANGES_CACHE_CONTROL


def test_tidying_after_the_switch_never_undoes_it():
    """Once the new version is written down as serving, a failure to rewrite a
    record is noted and the next thing is tried."""
    for name, following in (("ClearPending", "RetireOldRecord"),
                            ("RetireOldRecord", "UpdateRecord"),
                            ("UpdateRecord", "Done")):
        assert states()[name]["Catch"] == [
            {"ErrorEquals": ["States.ALL"], "ResultPath": "$.tidyError", "Next": following}
        ]


def test_a_launch_that_fails_leaves_the_serving_version_where_it_was():
    """Pending goes, the record says failed, and the run fails with the
    launch's own error — but current is untouched, so the account is not left
    with a version it never launched written down as serving."""
    assert states()["LaunchNew"]["Catch"] == [
        {"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure",
         "Next": "ClearPendingAfterFailure"}
    ]
    path = walk("ClearPendingAfterFailure")
    assert path == ["ClearPendingAfterFailure", "RecordFailure", "CouldNotLaunch"]
    assert "WriteCurrent" not in path
    assert states()["RecordFailure"]["Parameters"]["Body"]["status"] == "failed"
    assert states()["CouldNotLaunch"] == {
        "Type": "Fail", "ErrorPath": "$.failure.Error", "CausePath": "$.failure.Cause",
    }


def test_launching_retries_while_the_instance_profile_propagates():
    retry = states()["LaunchNew"]["Retry"][0]
    assert retry["MaxAttempts"] >= 10
    assert retry["IntervalSeconds"] <= 5


def test_nothing_waits():
    # A run is seconds; the waiting is the timer's, between runs.
    assert not any(state["Type"] == "Wait" for state in states().values())
    assert not any(".sync" in str(state.get("Resource", "")) for state in states().values())


def test_the_definition_serialises():
    assert json.loads(json.dumps(definition()))["StartAt"] == "ReadPending"


def test_every_next_names_a_state_that_exists():
    named = set()
    for state in states().values():
        for key in ("Next", "Default"):
            if key in state:
                named.add(state[key])
        for choice in state.get("Choices", []):
            named.add(choice["Next"])
        for catch in state.get("Catch", []):
            named.add(catch["Next"])
    assert named <= set(states()), named - set(states())
