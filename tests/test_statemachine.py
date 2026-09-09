"""The receiving state machine's definition: decide, record, answer.

It runs inside API Gateway's 29 seconds, so it never waits and never launches;
the switch is another machine's job. What is pinned here is the decision — when
an apply is refused, when it switches at once, when it is scheduled — and the
record the dashboard reads.
"""

import json

from constants import REGION

from enclavize.aws import apigw
from enclavize.logic import naming
from enclavize.logic import statemachine as sm

DASHBOARD_BUCKET = "enclavize-dashboard-123456789012"
SWITCH_ARN = f"arn:aws:states:{REGION}:123456789012:stateMachine:enclavize-apply-switch"
SCHEDULER_ROLE = "arn:aws:iam::123456789012:role/enclavize-apply-scheduler"
SCHEDULE = "enclavize-apply-switch"
CURRENT = "/enclavize/apply/current"
PENDING = "/enclavize/apply/pending"
DELAY = 300


def definition(delay=DELAY):
    return sm.build_definition(
        dashboard_bucket=DASHBOARD_BUCKET,
        switch_state_machine_arn=SWITCH_ARN,
        schedule_name=SCHEDULE,
        scheduler_role_arn=SCHEDULER_ROLE,
        current_param=CURRENT,
        pending_param=PENDING,
        delay_seconds=delay,
        in_flight_error=apigw.IN_FLIGHT_ERROR,
    )


def states():
    return definition()["States"]


def successors(state):
    out = [state[k] for k in ("Next", "Default") if k in state]
    out += [c["Next"] for c in state.get("Choices", [])]
    out += [c["Next"] for c in state.get("Catch", [])]
    return out


# --- refusing --------------------------------------------------------------


def test_an_apply_is_refused_while_one_is_in_flight():
    """One at a time. A second apply while one waits or switches would race it
    for the listener."""
    busy = states()["Busy?"]
    assert {c["Next"] for c in busy["Choices"]} == {"RefuseInFlight"}
    refusal = states()["RefuseInFlight"]
    assert refusal["Type"] == "Fail"
    # The same string the API turns into a 409.
    assert refusal["Error"] == apigw.IN_FLIGHT_ERROR


def test_in_flight_is_read_off_the_things_themselves():
    """The schedule and the switch's running executions, not a marker: a
    switch that died holds no slot, so a crash cannot jam the account for good."""
    running = states()["AnySwitchRunning"]
    assert running["Resource"] == "arn:aws:states:::aws-sdk:sfn:listExecutions"
    assert running["Parameters"]["StateMachineArn"] == SWITCH_ARN
    assert running["Parameters"]["StatusFilter"] == "RUNNING"

    scheduled = states()["AnyScheduled"]
    assert scheduled["Resource"] == "arn:aws:states:::aws-sdk:scheduler:getSchedule"
    assert scheduled["Parameters"] == {"Name": SCHEDULE}
    # No schedule is the ordinary case, not an error.
    assert scheduled["Catch"][0]["ErrorEquals"] == ["Scheduler.ResourceNotFoundException"]
    assert scheduled["Catch"][0]["Next"] == "Busy?"

    variables = {c["Variable"] for c in states()["Busy?"]["Choices"]}
    assert variables == {"$.running.Executions[0]", "$.scheduled.Arn"}
    assert "getParameter" not in json.dumps(states()["Busy?"])


# --- the first apply switches at once --------------------------------------


def test_nothing_serving_means_the_switch_starts_now():
    first = states()["First?"]
    assert first["Default"] == "SwitchNow"
    assert first["Choices"][0]["Variable"] == "$.current.Parameter.Value"
    assert first["Choices"][0]["Next"] == "WhenToSwitch"

    current = states()["AnyCurrent"]
    assert current["Parameters"] == {"Name": CURRENT}
    assert current["Catch"][0]["ErrorEquals"] == ["Ssm.ParameterNotFoundException"]


def test_the_switch_is_started_and_not_waited_for():
    start = states()["SwitchNow"]
    assert start["Resource"] == "arn:aws:states:::states:startExecution"
    assert ".sync" not in start["Resource"]
    assert start["Parameters"]["StateMachineArn"] == SWITCH_ARN
    assert start["Parameters"]["Input"] == {"commit.$": "$.commit", "at.$": "$.at", "immediate": True}


def test_an_immediate_switch_answers_switching():
    outcome = states()["DescribeSwitching"]["Parameters"]
    assert outcome["status"] == "switching"
    assert outcome["switchAt.$"] == "$.at"
    assert states()["DescribeSwitching"]["Next"] == "RecordApply"


# --- every later apply is scheduled ----------------------------------------


def test_the_switch_time_is_the_receipt_plus_the_delay():
    """The only JSONata in the definition: JSONPath's intrinsics cannot add to
    a timestamp, and a one-time schedule needs `at(yyyy-mm-ddThh:mm:ss)`."""
    when = states()["WhenToSwitch"]
    assert when["Type"] == "Pass"
    assert when["QueryLanguage"] == "JSONata"
    expression = when["Output"]
    assert expression.startswith("{%") and expression.endswith("%}")
    assert f"$toMillis($states.input.at) + {DELAY * 1000}" in expression
    assert "'at(' & $fromMillis($when, '[Y0001]-[M01]-[D01]T[H01]:[m01]:[s01]') & ')'" in expression
    assert "'status': 'scheduled'" in expression

    assert f"+ {3600 * 1000}" in definition(delay=3600)["States"]["WhenToSwitch"]["Output"]


def test_jsonata_is_confined_to_the_states_that_need_it():
    """Three: the one that adds to a timestamp, and the two that pick keys out
    of a listing. Everything else stays JSONPath, so the definition is not
    two dialects for no reason."""
    speaking = [name for name, s in states().items() if s.get("QueryLanguage") == "JSONata"]
    assert speaking == ["WhenToSwitch", "WriteMonthIndex", "WriteManifest"]
    assert "QueryLanguage" not in definition()


def test_the_serving_version_is_told_before_the_timer_is_set():
    """Written first, so the version serving learns what is coming even if
    scheduling then fails — in which case the apply fails and the next one
    overwrites this."""
    assert states()["WhenToSwitch"]["Next"] == "WritePending"
    pending = states()["WritePending"]
    assert pending["Resource"] == "arn:aws:states:::aws-sdk:ssm:putParameter"
    assert pending["Parameters"]["Name"] == PENDING
    assert pending["Parameters"]["Value.$"] == "$.schedule.pendingValue"
    assert pending["Parameters"]["Overwrite"] is True
    assert pending["Next"] == "CreateSchedule"
    # What the version reads: the commit and when.
    assert "'pendingValue': $string({'commit': $states.input.commit, 'switchAt': $switchAt})" \
        in states()["WhenToSwitch"]["Output"]


def test_the_timer_fires_the_switch_once_and_then_goes():
    schedule = states()["CreateSchedule"]
    assert schedule["Resource"] == "arn:aws:states:::aws-sdk:scheduler:createSchedule"
    parameters = schedule["Parameters"]
    assert parameters["Name"] == SCHEDULE
    assert parameters["ScheduleExpression.$"] == "$.schedule.expression"
    assert parameters["ScheduleExpressionTimezone"] == "UTC"
    assert parameters["FlexibleTimeWindow"] == {"Mode": "OFF"}
    # Gone once fired: its absence is how the next apply tells pending from
    # already started.
    assert parameters["ActionAfterCompletion"] == "DELETE"
    assert parameters["Target"]["Arn"] == SWITCH_ARN
    assert parameters["Target"]["RoleArn"] == SCHEDULER_ROLE
    assert parameters["Target"]["Input.$"] == "$.schedule.input"
    assert "'immediate': false" in states()["WhenToSwitch"]["Output"]


def test_a_decision_that_fails_fails_the_apply():
    """Unlike the bookkeeping, these must not be caught and carried on from: an
    apply that could not be scheduled has to say so."""
    for name in ("AnySwitchRunning", "SwitchNow", "WritePending", "CreateSchedule"):
        assert "Catch" not in states()[name], name
    for name in ("AnyScheduled", "AnyCurrent"):
        caught = [c["ErrorEquals"] for c in states()[name]["Catch"]]
        assert ["States.ALL"] not in caught, name


# --- the record and the index ----------------------------------------------


def test_every_apply_is_recorded_with_its_outcome():
    record = states()["RecordApply"]
    assert record["Resource"] == "arn:aws:states:::aws-sdk:s3:putObject"
    assert record["Parameters"]["Bucket"] == DASHBOARD_BUCKET
    body = record["Parameters"]["Body"]
    assert body["status.$"] == "$.outcome.status"
    assert body["switchAt.$"] == "$.outcome.switchAt"
    assert body["startedAt.$"] == "$.at"
    # Rewritten by the switch as it goes, so it must not be cached like the
    # page beside it.
    assert record["Parameters"]["CacheControl"] == naming.CHANGES_CACHE_CONTROL


def test_applying_the_same_commit_twice_leaves_two_records():
    """The time leads the key, so a second apply cannot overwrite the first. It
    leads rather than trails because that is also what makes the keys sort in
    the order things happened."""
    key = states()["RecordApply"]["Parameters"]["Key.$"]
    assert key == "States.Format('applies/{}_{}.json', $.at, $.commit)"


def test_the_key_the_helper_builds_is_the_key_that_gets_written():
    """The state machine writes these keys; tests and tooling build them with
    the helper. Two definitions of one shape, so they are pinned to each other."""
    expression = states()["RecordApply"]["Parameters"]["Key.$"]
    template = expression.split("'")[1]
    assert template.format("AT", "SHA") == naming.apply_record_key("AT", "SHA")


def test_the_time_is_stamped_once_and_then_reused():
    """Read afresh in each state it drifts by milliseconds, and an apply landing
    on the last instant of a month would be filed under the next one."""
    assert states()["Stamp"]["Parameters"]["at.$"] == "$$.State.EnteredTime"
    after = {name: s for name, s in states().items() if name != "Stamp"}
    assert "$$.State.EnteredTime" not in json.dumps(after)


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
    """A listing comes back as objects full of ETags and storage classes, and
    the page wants only the keys — which is what these are public for.

    The brackets are the point of the assertion. JSONata unwraps a path that
    yields one value, so a month with a single apply would otherwise arrive as
    a bare string; and a listing with nothing in it has no Contents, which the
    brackets turn into an empty array rather than an error. Neither case is
    something an offline test can execute, so the shape is pinned here and
    the first apply of every cycle proves it."""
    month = states()["WriteMonthIndex"]["Arguments"]["Body"]
    assert month["applies"] == "{% [$states.input.page.Contents.Key] %}"
    assert month["month"] == "{% $states.input.month.name %}"
    manifest = states()["WriteManifest"]["Arguments"]
    assert manifest["Key"] == naming.APPLIES_MANIFEST_KEY
    assert manifest["Body"]["months"] == "{% [$states.input.months.Contents.Key] %}"
    assert states()["ListMonths"]["Parameters"]["Prefix"] == naming.APPLIES_INDEX_PREFIX


def test_the_index_writers_pass_the_decision_through():
    """A JSONata state's Output replaces the state's output outright, so what
    Done needs — the commit and the outcome — has to be carried by hand."""
    for name in ("WriteMonthIndex", "WriteManifest"):
        assert states()[name]["Output"] == "{% $states.input %}"


def test_the_month_index_key_is_the_helper_key():
    key = states()["WriteMonthIndex"]["Arguments"]["Key"]
    assert key == f"{{% '{naming.APPLIES_INDEX_PREFIX}' & $states.input.month.name & '.json' %}}"
    assert naming.apply_month_key("2026-09") == f"{naming.APPLIES_INDEX_PREFIX}2026-09.json"


def test_a_month_too_busy_to_list_says_so():
    """One listing caps at a thousand keys and this makes no second call, so the
    alternative to saying so is quietly showing part of a month. Guarded, so a
    listing without the field reads as not truncated rather than as an error."""
    body = states()["WriteMonthIndex"]["Arguments"]["Body"]
    assert body["truncated"] == "{% $states.input.page.IsTruncated ? true : false %}"


def test_what_the_dashboard_rereads_is_not_cached_like_the_rest():
    for name in ("WriteMonthIndex", "WriteManifest"):
        assert states()[name]["Arguments"]["CacheControl"] == naming.CHANGES_CACHE_CONTROL


def test_no_bookkeeping_failure_can_report_a_failed_apply():
    """By the time any of this runs the switch has been started or scheduled.
    Letting a listing hiccup fail the execution would have the API answer that
    the apply failed, for work going ahead regardless."""
    bookkeeping = ["RecordApply", "ListMonth", "WriteMonthIndex", "ListMonths", "WriteManifest"]

    # Every task with a catch-all is bookkeeping, and every piece of
    # bookkeeping has one — so a new task cannot be added without saying which.
    catching = [name for name, s in states().items()
                if s["Type"] == "Task"
                and any(c["ErrorEquals"] == ["States.ALL"] for c in s.get("Catch", []))]
    assert catching == bookkeeping

    for name in bookkeeping:
        catch = states()[name]["Catch"][0]
        assert catch["Next"] == "Done"
        # Without this the error replaces the input, and Done answers with
        # nothing. A JSONata state has no ResultPath and carries the input
        # through by hand instead.
        if states()[name].get("QueryLanguage") == "JSONata":
            assert catch["Output"] == "{% $merge([$states.input, {'indexError': $states.errorOutput}]) %}"
        else:
            assert catch["ResultPath"] == "$.indexError"


# --- the answer ------------------------------------------------------------


def test_it_answers_with_what_will_happen_and_when():
    """"switching" or "scheduled", never "applied": the switch has only just
    started, or not yet. The dashboard is where it is watched."""
    done = states()["Done"]
    assert done["End"] is True
    assert done["Parameters"] == {
        "commit.$": "$.commit",
        "status.$": "$.outcome.status",
        "switchAt.$": "$.outcome.switchAt",
    }


def test_no_state_waits():
    """Express tops out at five minutes and the API integration at 29 seconds."""
    assert not any(state["Type"] == "Wait" for state in states().values())
    assert not any(".sync" in str(state.get("Resource", "")) for state in states().values())


def test_both_branches_reach_the_record_and_the_answer():
    for start in ("SwitchNow", "WhenToSwitch"):
        seen, stack = set(), [start]
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            stack.extend(successors(states()[name]))
        assert {"RecordApply", "Done"} <= seen, start


def test_every_transition_resolves():
    for name, state in states().items():
        for target in successors(state):
            assert target in states(), (name, target)


def test_the_definition_serialises():
    # It is sent as a JSON string, so anything unserialisable fails at create
    # time deep inside the bring-up.
    assert json.loads(json.dumps(definition()))["StartAt"] == "Stamp"
