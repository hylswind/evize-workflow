"""The apply state machine definition.

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


def definition():
    return sm.build_definition(
        app_repo=APP_REPO,
        domain=DOMAIN,
        image_id="ami-1",
        instance_type=setup_config.APPLY_INSTANCE_TYPE,
        subnet_id="subnet-1",
        instance_profile="enclavize-apply",
        dashboard_bucket=DASHBOARD_BUCKET,
        name_tag="enclavize-apply",
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
    something enclavize cannot vary, and the commit is already what the repo was
    checked out at — so neither belongs in an application's environment."""
    exported = [line for line in user_data_expression().splitlines()
                if line.startswith("export ")]
    assert exported == [f"export ENCLAVIZE_DOMAIN={DOMAIN}"]


def test_it_launches_with_the_bounded_apply_profile():
    launch = definition()["States"]["LaunchInstance"]
    assert launch["Resource"] == "arn:aws:states:::aws-sdk:ec2:runInstances"
    assert launch["Parameters"]["IamInstanceProfile"] == {"Name": "enclavize-apply"}
    assert launch["Parameters"]["UserData.$"] == "$.userData"


def test_launching_retries_while_the_instance_profile_propagates():
    # The same delay that the sealing launch has to absorb.
    retry = definition()["States"]["LaunchInstance"]["Retry"][0]
    assert retry["MaxAttempts"] >= 10
    assert retry["IntervalSeconds"] <= 5


def test_every_apply_is_recorded_for_the_dashboard():
    record = definition()["States"]["RecordApply"]
    assert record["Resource"] == "arn:aws:states:::aws-sdk:s3:putObject"
    assert record["Parameters"]["Bucket"] == DASHBOARD_BUCKET
    assert record["Parameters"]["Body"]["instanceId.$"] == "$.launch.Instances[0].InstanceId"


def test_applying_the_same_commit_twice_leaves_two_records():
    """The time leads the key, so a second apply cannot overwrite the first. It
    leads rather than trails because that is also what makes the keys sort in
    the order things happened."""
    key = definition()["States"]["RecordApply"]["Parameters"]["Key.$"]
    assert key == "States.Format('applies/{}_{}.json', $.at, $.commit)"


def test_the_key_the_helper_builds_is_the_key_that_gets_written():
    """The state machine writes these keys; tests and tooling build them with
    the helper. Two definitions of one shape, so they are pinned to each other."""
    expression = definition()["States"]["RecordApply"]["Parameters"]["Key.$"]
    template = expression.split("'")[1]
    assert template.format("AT", "SHA") == naming.apply_record_key("AT", "SHA")


def test_the_time_is_stamped_once_and_then_reused():
    """Read afresh in each state it drifts by milliseconds, and an apply landing
    on the last instant of a month would be filed under the next one."""
    states = definition()["States"]
    assert states["RenderUserData"]["Parameters"]["at.$"] == "$$.State.EnteredTime"
    assert states["RecordApply"]["Parameters"]["Body"]["startedAt.$"] == "$.at"
    after = {name: s for name, s in states.items() if name != "RenderUserData"}
    assert "$$.State.EnteredTime" not in json.dumps(after)


# --- the index the dashboard reads ---------------------------------------


def test_the_index_is_rebuilt_from_listings_rather_than_appended_to():
    """A listing is idempotent, so a half-written index heals itself on the next
    apply instead of drifting. It is also the only thing the language can do:
    there is no intrinsic for appending to an array."""
    states = definition()["States"]
    assert states["ListMonth"]["Resource"].endswith("s3:listObjectsV2")
    assert states["ListMonths"]["Resource"].endswith("s3:listObjectsV2")
    assert "getObject" not in json.dumps(states)


def test_one_month_is_one_listing():
    """Record keys open with the timestamp, so a month is a prefix — which is
    what spares this a continuation loop it has no counter for."""
    states = definition()["States"]
    assert states["ListMonth"]["Parameters"]["Prefix.$"] == (
        "States.Format('applies/{}', $.month.name)"
    )
    assert states["WhichMonth"]["Parameters"]["name.$"] == (
        "States.Format('{}-{}', "
        "States.ArrayGetItem(States.StringSplit($.at, '-'), 0), "
        "States.ArrayGetItem(States.StringSplit($.at, '-'), 1))"
    )


def test_a_months_listing_cannot_pick_up_a_shard():
    """The shards live under the same prefix as the records they index."""
    assert not naming.apply_month_key("2026-08").startswith(
        naming.apply_month_prefix("2026-08")
    )


def test_the_manifest_names_the_months_and_nothing_else():
    states = definition()["States"]
    assert states["ListMonths"]["Parameters"]["Prefix"] == naming.APPLIES_INDEX_PREFIX
    manifest = states["WriteManifest"]["Parameters"]
    assert manifest["Key"] == naming.APPLIES_MANIFEST_KEY
    assert manifest["Body"]["months.$"] == "$.months.Contents"


def test_a_month_too_busy_to_list_says_so():
    """One listing caps at a thousand keys and this makes no second call, so the
    alternative to saying so is quietly showing part of a month."""
    body = definition()["States"]["WriteMonthIndex"]["Parameters"]["Body"]
    assert body["truncated.$"] == "$.page.IsTruncated"


def test_what_the_dashboard_rereads_is_not_cached_like_the_rest():
    states = definition()["States"]
    for name in ("WriteMonthIndex", "WriteManifest"):
        assert states[name]["Parameters"]["CacheControl"] == naming.CHANGES_CACHE_CONTROL


def test_no_bookkeeping_failure_can_report_a_failed_apply():
    """By the time any of this runs the instance is up and applying the commit.
    Letting a listing hiccup fail the execution would have the API answer that
    the apply failed, for work going ahead regardless."""
    states = definition()["States"]
    bookkeeping = ["RecordApply", "ListMonth", "WriteMonthIndex", "ListMonths",
                   "WriteManifest"]

    # Every task but the launch itself, so a new one cannot be added without a
    # catch of its own.
    assert [name for name, s in states.items()
            if s["Type"] == "Task" and name != "LaunchInstance"] == bookkeeping

    for name in bookkeeping:
        catch = states[name]["Catch"][0]
        assert catch["ErrorEquals"] == ["States.ALL"]
        assert catch["Next"] == "Done"
        # Without this the error replaces the input, and Done answers with the
        # instance the launch returned.
        assert catch["ResultPath"] == "$.indexError"


def test_it_returns_as_soon_as_the_instance_exists():
    """It must not wait for the commit to finish: Express tops out at five minutes and the
    API integration at 29 seconds."""
    done = definition()["States"]["Done"]
    assert done["End"] is True
    # "launched", not "applied" — the instance has only just started.
    assert done["Parameters"]["status"] == "launched"
    assert done["Parameters"]["instanceId.$"] == "$.launch.Instances[0].InstanceId"


def test_no_state_waits_on_the_apply_finishing():
    states = definition()["States"]
    assert not any(state["Type"] == "Wait" for state in states.values())
    # A .sync task would block until the work completed.
    assert not any(".sync" in str(state.get("Resource", "")) for state in states.values())


def test_the_definition_serialises():
    # It is sent as a JSON string, so anything unserialisable fails at create
    # time deep inside the bring-up.
    assert json.loads(json.dumps(definition()))["StartAt"] == "RenderUserData"
