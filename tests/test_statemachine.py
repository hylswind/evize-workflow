"""The receiving state machine's definition.

The escaping rules here come from the Amazon States Language spec: ' { } and \\
are reserved inside an intrinsic invocation and each must be preceded by a
backslash.
"""

import json

from constants import APP_REPO, DOMAIN, REGION

from enclavize.logic import naming
from enclavize.logic import statemachine as sm
from setup import config as setup_config

DASHBOARD_BUCKET = "enclavize-dashboard-123456789012"
CHECK_ARN = f"arn:aws:states:{REGION}:123456789012:stateMachine:enclavize-apply-check"
SCHEDULE = "enclavize-apply-check"
CURRENT, PENDING, READY = (f"/enclavize/apply/{w}" for w in ("current", "pending", "ready"))


def definition():
    return sm.build_definition(
        app_repo=APP_REPO,
        domain=DOMAIN,
        image_id="ami-1",
        instance_type=setup_config.APPLY_INSTANCE_TYPE,
        subnet_id="subnet-1",
        instance_profile="enclavize-apply",
        name_tag="enclavize-apply",
        dashboard_bucket=DASHBOARD_BUCKET,
        check_state_machine_arn=CHECK_ARN,
        schedule_name=SCHEDULE,
        scheduler_role_arn="arn:aws:iam::123456789012:role/enclavize-apply-scheduler",
        check_interval_minutes=5,
        current_param=CURRENT,
        pending_param=PENDING,
        ready_param=READY,
        in_flight_error="ApplyInFlight",
    )


def states():
    return definition()["States"]


def walk(start, *, choose=None):
    """The states visited from `start`, following Next and the branch a Choice
    is told to take, until an End."""
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


def exported(expression):
    return [line for line in expression.splitlines() if line.startswith("export ")]


NEW_PATH = {"Busy?": "AnyCurrent", "First?": "RenderNew"}
UPDATE_PATH = {"Busy?": "AnyCurrent", "First?": "Prepare"}


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


# --- what an instance is handed --------------------------------------------


def new_user_data():
    return states()["RenderNew"]["Parameters"]["userData.$"]


def preparer_user_data():
    return states()["RenderPreparer"]["Parameters"]["userData.$"]


def test_a_new_instance_is_told_the_domain_and_that_it_is_new_and_nothing_else():
    """The contract the README states, pinned here. A region would advertise
    something enclavize cannot vary, and the commit is already what the repo was
    checked out at — so neither belongs in an application's environment."""
    assert exported(new_user_data()) == [
        f"export ENCLAVIZE_DOMAIN={DOMAIN}",
        "export ENCLAVIZE_MODE=NEW",
    ]


def test_a_preparer_is_told_which_commit_it_is_preparing_for():
    assert exported(preparer_user_data()) == [
        f"export ENCLAVIZE_DOMAIN={DOMAIN}",
        "export ENCLAVIZE_MODE=UPDATE",
        "export ENCLAVIZE_NEXT_COMMIT={}",
    ]


def test_a_new_instance_checks_out_the_commit_applied():
    expression = new_user_data()
    assert expression.count("{}") == 1
    assert expression.endswith("$.commit))")


def test_a_preparer_checks_out_the_serving_commit_not_the_new_one():
    """It is the serving version being given the chance to prepare. The new
    commit fills the second slot, the one the export line above names."""
    expression = preparer_user_data()
    assert expression.count("{}") == 2
    assert expression.endswith("$.pending.previous.commit, $.commit))")


def test_the_user_data_is_base64_encoded_because_run_instances_expects_that():
    for expression in (new_user_data(), preparer_user_data()):
        assert expression.startswith("States.Base64Encode(States.Format(")


def test_the_script_clones_the_app_repo_and_runs_its_entrypoint():
    for expression in (new_user_data(), preparer_user_data()):
        assert f"git clone https://github.com/{APP_REPO}.git /opt/app" in expression
        assert "exec ./setup.sh" in expression


def test_the_script_fails_fast():
    assert "#!/bin/bash\nset -euxo pipefail" in new_user_data()


def test_no_instance_carries_the_api_key():
    """It has no business holding the key that triggers applies: a commit that
    could read it could apply another one."""
    assert "APPLY_API_KEY" not in json.dumps(definition())


def test_the_script_stops_tracing_before_exporting_anything():
    for expression in (new_user_data(), preparer_user_data()):
        assert expression.index("set +x") < expression.index("export ENCLAVIZE_DOMAIN")


def test_the_ready_flags_name_is_fixed_rather_than_handed_over():
    """Like the port an application would answer on, the parameter it writes
    is part of the contract, not of the environment. The environment carries
    what differs from one launch to the next."""
    assert READY not in new_user_data()
    assert READY not in preparer_user_data()


# --- the launches ----------------------------------------------------------


def test_both_launches_use_the_bounded_apply_profile():
    for name in ("LaunchNew", "LaunchPreparer"):
        launch = states()[name]
        assert launch["Resource"] == "arn:aws:states:::aws-sdk:ec2:runInstances"
        assert launch["Parameters"]["IamInstanceProfile"] == {"Name": "enclavize-apply"}


def test_launching_retries_while_the_instance_profile_propagates():
    # The same delay that the sealing launch has to absorb.
    for name in ("LaunchNew", "LaunchPreparer"):
        retry = states()[name]["Retry"][0]
        assert retry["MaxAttempts"] >= 10
        assert retry["IntervalSeconds"] <= 5


def tags_of(launch):
    return {t["Key"]: t.get("Value", t.get("Value.$"))
            for t in launch["Parameters"]["TagSpecifications"][0]["Tags"]}


def test_a_new_instance_is_tagged_with_its_commit():
    assert tags_of(states()["LaunchNew"]) == {
        "Name": "enclavize-apply", naming.COMMIT_TAG: "$.commit",
    }


def test_a_preparer_is_tagged_with_the_commit_it_runs_and_the_one_it_prepares_for():
    """The second tag is how the check machine finds a preparer that never said
    ready, to stop it before the new commit goes in."""
    assert tags_of(states()["LaunchPreparer"]) == {
        "Name": "enclavize-apply",
        naming.COMMIT_TAG: "$.pending.previous.commit",
        naming.PREPARING_FOR_TAG: "$.commit",
    }


def test_a_preparer_terminates_when_it_shuts_itself_down():
    """The application ends its preparation with a shutdown, and there is
    nothing to keep: the instance ran the serving commit, for its say and
    nothing else. A new instance is not launched that way — it is the version
    that serves."""
    assert states()["LaunchPreparer"]["Parameters"]["InstanceInitiatedShutdownBehavior"] == "terminate"
    assert "InstanceInitiatedShutdownBehavior" not in states()["LaunchNew"]["Parameters"]


# --- deciding -------------------------------------------------------------


def test_the_first_apply_launches_at_once_and_says_so():
    """Nothing serving means nobody to prepare."""
    path = walk("Stamp", choose=NEW_PATH)
    assert "LaunchNew" in path
    assert "LaunchPreparer" not in path
    assert "CreateSchedule" not in path
    assert path[-1] == "Done"
    assert states()["RecordLaunched"]["Parameters"]["status"] == "launched"


def test_a_later_apply_launches_a_preparer_and_says_so():
    path = walk("Stamp", choose=UPDATE_PATH)
    assert "LaunchPreparer" in path
    assert "LaunchNew" not in path
    assert path[-1] == "Done"
    assert states()["RecordPreparing"]["Parameters"]["status"] == "preparing"


def test_which_branch_is_decided_by_whether_anything_is_serving():
    current = states()["AnyCurrent"]
    assert current["Resource"] == "arn:aws:states:::aws-sdk:ssm:getParameter"
    assert current["Parameters"] == {"Name": CURRENT}
    # Absent is not an error: it is the first apply.
    assert current["Catch"][0]["ErrorEquals"] == ["Ssm.ParameterNotFoundException"]
    first = states()["First?"]
    assert first["Choices"] == [
        {"Variable": "$.current.Parameter.Value", "IsPresent": True, "Next": "Prepare"}
    ]
    assert first["Default"] == "RenderNew"


def test_an_apply_is_refused_while_the_timer_stands_or_the_check_is_running():
    """Either is an apply in flight: the timer while one waits on its
    preparer, the check while one is being switched. A second apply then would
    overwrite what the first wrote."""
    busy = states()["Busy?"]
    assert {c["Variable"] for c in busy["Choices"]} == {
        "$.scheduled.Arn", "$.running.Executions[0]",
    }
    assert all(c["Next"] == "RefuseInFlight" for c in busy["Choices"])
    assert states()["RefuseInFlight"] == {
        "Type": "Fail", "Error": "ApplyInFlight",
        "Cause": "an apply is already preparing or switching; wait for it to finish",
    }


def test_in_flight_is_read_off_the_timer_and_the_check_not_off_a_marker():
    """A check that died holds no slot this way, so a crash cannot leave the
    account refusing every apply for good."""
    scheduled = states()["AnyScheduled"]
    assert scheduled["Resource"] == "arn:aws:states:::aws-sdk:scheduler:getSchedule"
    assert scheduled["Parameters"] == {"Name": SCHEDULE}
    assert scheduled["Catch"][0]["ErrorEquals"] == ["Scheduler.ResourceNotFoundException"]
    running = states()["AnyCheckRunning"]
    assert running["Resource"] == "arn:aws:states:::aws-sdk:sfn:listExecutions"
    assert running["Parameters"]["StateMachineArn"] == CHECK_ARN
    assert running["Parameters"]["StatusFilter"] == "RUNNING"


def test_the_refusal_comes_before_anything_is_touched():
    path = walk("Stamp", choose={"Busy?": "RefuseInFlight"})
    assert path[-1] == "RefuseInFlight"
    assert all(states()[n]["Type"] != "Task" or n in ("AnyScheduled", "AnyCheckRunning")
               for n in path)


# --- the first apply's bookkeeping ---------------------------------------


def test_a_new_launch_is_written_down_as_serving():
    """From here until the next switch, this is what the account says is
    serving — and what a later apply's preparer will be told about."""
    path = walk("Stamp", choose=NEW_PATH)
    assert path.index("LaunchNew") < path.index("WriteCurrent") < path.index("RecordApply")
    serving = states()["DescribeLaunched"]["Parameters"]
    assert serving == {
        "commit.$": "$.commit", "instanceId.$": "$.launch.instanceId",
        "startedAt.$": "$.at", "since.$": "$.at", "recordKey.$": "$.recordKey",
    }
    write = states()["WriteCurrent"]
    assert write["Parameters"]["Name"] == CURRENT
    assert write["Parameters"]["Value.$"] == "States.JsonToString($.serving)"


# --- the later apply's arrangements ---------------------------------------


def test_the_pending_parameter_carries_everything_the_check_will_need():
    """The timer starts the check with no input at all, so the commit, the
    time, the record and what is serving all have to be in the parameter."""
    pending = states()["Prepare"]["Parameters"]["pending"]
    assert pending == {
        "commit.$": "$.commit",
        "at.$": "$.at",
        "recordKey.$": "$.recordKey",
        "previous.$": "States.StringToJson($.current.Parameter.Value)",
    }
    write = states()["WritePending"]
    assert write["Parameters"]["Name"] == PENDING
    assert write["Parameters"]["Value.$"] == "States.JsonToString($.pending)"


def test_the_timer_looks_every_few_minutes_and_is_not_its_own_to_delete():
    """Recurring, and taken down by the check machine: its standing is what
    says an apply is in flight, and deleting it is how the check claims the
    switch."""
    create = states()["CreateSchedule"]
    assert create["Resource"] == "arn:aws:states:::aws-sdk:scheduler:createSchedule"
    assert create["Parameters"]["Name"] == SCHEDULE
    assert create["Parameters"]["ScheduleExpression"] == "rate(5 minutes)"
    assert create["Parameters"]["ActionAfterCompletion"] == "NONE"
    assert create["Parameters"]["Target"]["Arn"] == CHECK_ARN
    assert create["Parameters"]["Target"]["Input"] == "{}"


def test_the_rate_is_spelled_the_way_scheduler_wants_it():
    assert sm.rate_expression(1) == "rate(1 minute)"
    assert sm.rate_expression(5) == "rate(5 minutes)"


def test_a_stale_ready_is_cleared_before_pending_is_written_and_the_preparer_last():
    """The order the preparer relies on: by the time it can say ready, the
    pending it will be compared against and the timer that will read it are
    both in place. And a ready left over from an earlier apply must not count
    for this one."""
    path = walk("Stamp", choose=UPDATE_PATH)
    assert (path.index("ClearStaleReady") < path.index("WritePending")
            < path.index("CreateSchedule") < path.index("LaunchPreparer"))
    clear = states()["ClearStaleReady"]
    assert clear["Resource"] == "arn:aws:states:::aws-sdk:ssm:deleteParameter"
    assert clear["Parameters"] == {"Name": READY}
    assert clear["Catch"][0]["ErrorEquals"] == ["Ssm.ParameterNotFoundException"]


def test_a_preparer_that_fails_to_launch_takes_the_timer_and_pending_with_it():
    """Left standing, the timer would count seven days towards a switch nobody
    was preparing for, refusing every apply meanwhile."""
    assert states()["LaunchPreparer"]["Catch"][0]["Next"] == "UnwindSchedule"
    assert states()["CreateSchedule"]["Catch"][0]["Next"] == "UnwindPending"
    unwind = walk("UnwindSchedule")
    assert unwind == ["UnwindSchedule", "UnwindPending", "CouldNotPrepare"]
    assert states()["UnwindSchedule"]["Parameters"] == {"Name": SCHEDULE}
    assert states()["UnwindPending"]["Parameters"] == {"Name": PENDING}
    assert states()["CouldNotPrepare"]["Type"] == "Fail"


def test_the_answer_to_a_later_apply_names_what_is_serving():
    record = states()["RecordPreparing"]["Parameters"]
    assert record["previous.$"] == "$.pending.previous.commit"
    assert record["preparerId.$"] == "$.launch.instanceId"


# --- the record -----------------------------------------------------------


def test_every_apply_is_recorded_for_the_dashboard():
    record = states()["RecordApply"]
    assert record["Resource"] == "arn:aws:states:::aws-sdk:s3:putObject"
    assert record["Parameters"]["Bucket"] == DASHBOARD_BUCKET
    assert record["Parameters"]["Key.$"] == "$.recordKey"
    assert record["Parameters"]["Body.$"] == "$.record"


def test_the_record_is_not_cached_because_the_check_rewrites_it():
    assert states()["RecordApply"]["Parameters"]["CacheControl"] == naming.CHANGES_CACHE_CONTROL


def test_applying_the_same_commit_twice_leaves_two_records():
    """The time leads the key, so a second apply cannot overwrite the first. It
    leads rather than trails because that is also what makes the keys sort in
    the order things happened."""
    key = states()["Stamp"]["Parameters"]["recordKey.$"]
    assert key == "States.Format('applies/{}_{}.json', $$.State.EnteredTime, $.commit)"


def test_the_key_the_helper_builds_is_the_key_that_gets_written():
    """The state machine writes these keys; tests and tooling build them with
    the helper. Two definitions of one shape, so they are pinned to each other."""
    expression = states()["Stamp"]["Parameters"]["recordKey.$"]
    template = expression.split("'")[1]
    assert template.format("AT", "SHA") == naming.apply_record_key("AT", "SHA")


def test_the_time_is_stamped_once_and_then_reused():
    """Read afresh in each state it drifts by milliseconds, and an apply landing
    on the last instant of a month would be filed under the next one."""
    assert states()["Stamp"]["Parameters"]["at.$"] == "$$.State.EnteredTime"
    after = {name: s for name, s in states().items() if name != "Stamp"}
    assert "$$.State.EnteredTime" not in json.dumps(after)


def test_the_answer_is_the_record():
    """What the API says and what the dashboard shows are one object."""
    done = states()["Done"]
    assert done["End"] is True
    assert done["OutputPath"] == "$.record"
    for name in ("RecordLaunched", "RecordPreparing"):
        assert states()[name]["ResultPath"] == "$.record"
        assert "startedAt.$" in states()[name]["Parameters"]


# --- the index the dashboard reads ---------------------------------------


def test_the_index_is_rebuilt_from_listings_rather_than_appended_to():
    """A listing is idempotent, so a half-written index heals itself on the next
    apply instead of drifting. It is also the only thing the language can do:
    there is no intrinsic for appending to an array."""
    assert states()["ListMonth"]["Resource"].endswith("s3:listObjectsV2")
    assert states()["ListMonths"]["Resource"].endswith("s3:listObjectsV2")
    assert "getObject" not in json.dumps(states())


def test_one_month_is_one_listing():
    """Record keys open with the timestamp, so a month is a prefix — which is
    what spares this a continuation loop it has no counter for."""
    assert states()["ListMonth"]["Parameters"]["Prefix.$"] == (
        "States.Format('applies/{}', $.month.name)"
    )
    assert states()["WhichMonth"]["Parameters"]["name.$"] == (
        "States.Format('{}-{}', "
        "States.ArrayGetItem(States.StringSplit($.at, '-'), 0), "
        "States.ArrayGetItem(States.StringSplit($.at, '-'), 1))"
    )


def test_a_months_listing_cannot_pick_up_a_shard():
    """The shards live under the same prefix as the records they index."""
    assert not naming.apply_month_key("2026-08").startswith(
        naming.apply_month_prefix("2026-08")
    )


def test_the_index_holds_keys_and_nothing_else():
    """A listing comes back full of ETags and storage classes; the page is
    public and wants only the keys. The brackets are what make the result an
    array even for a month with one apply, or none."""
    month = states()["WriteMonthIndex"]
    assert month["QueryLanguage"] == "JSONata"
    assert month["Arguments"]["Body"]["applies"] == "{% [$states.input.page.Contents.Key] %}"
    manifest = states()["WriteManifest"]
    assert manifest["QueryLanguage"] == "JSONata"
    assert manifest["Arguments"]["Key"] == naming.APPLIES_MANIFEST_KEY
    assert manifest["Arguments"]["Body"]["months"] == "{% [$states.input.months.Contents.Key] %}"


def test_jsonata_is_confined_to_the_two_index_writers():
    # Everything else speaks JSONPath, so the two dialects do not mix further
    # than they have to.
    speaking = {name for name, s in states().items() if s.get("QueryLanguage") == "JSONata"}
    assert speaking == {"WriteMonthIndex", "WriteManifest"}


def test_a_month_too_busy_to_list_says_so():
    """One listing caps at a thousand keys and this makes no second call, so the
    alternative to saying so is quietly showing part of a month."""
    body = states()["WriteMonthIndex"]["Arguments"]["Body"]
    assert body["truncated"] == "{% $states.input.page.IsTruncated ? true : false %}"


def test_what_the_dashboard_rereads_is_not_cached_like_the_rest():
    for name in ("WriteMonthIndex", "WriteManifest"):
        assert states()[name]["Arguments"]["CacheControl"] == naming.CHANGES_CACHE_CONTROL


def test_no_bookkeeping_failure_can_report_a_failed_apply():
    """By the time any of this runs the instance is up. Letting a listing
    hiccup fail the execution would have the API answer that the apply failed,
    for work going ahead regardless."""
    bookkeeping = ["RecordApply", "ListMonth", "WriteMonthIndex", "ListMonths", "WriteManifest"]
    for name in bookkeeping:
        catch = states()[name]["Catch"][0]
        assert catch["ErrorEquals"] == ["States.ALL"]
        assert catch["Next"] == "Done"
    # Every state after the launches is one of these, so a new one cannot be
    # added without a catch of its own.
    for choose in (NEW_PATH, UPDATE_PATH):
        path = walk("Stamp", choose=choose)
        launch = "LaunchNew" if choose is NEW_PATH else "LaunchPreparer"
        after = [n for n in path[path.index(launch) + 1:] if states()[n]["Type"] == "Task"]
        expected = (["WriteCurrent"] if choose is NEW_PATH else []) + bookkeeping
        assert after == expected


def test_it_returns_as_soon_as_the_instance_exists():
    """It must not wait for the commit to finish: Express tops out at five
    minutes and the API integration at 29 seconds."""
    assert not any(state["Type"] == "Wait" for state in states().values())
    # A .sync task would block until the work completed.
    assert not any(".sync" in str(state.get("Resource", "")) for state in states().values())


def test_the_definition_serialises():
    # It is sent as a JSON string, so anything unserialisable fails at create
    # time deep inside the bring-up.
    assert json.loads(json.dumps(definition()))["StartAt"] == "Stamp"


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
