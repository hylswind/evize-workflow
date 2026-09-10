"""Stage 3: apply a commit, then apply another while it serves.

Two layers, kept apart on purpose.

The first is enclavize's own contract, and it holds for *any* application: a
repository with an executable setup.sh at its root. Post a commit, an instance
runs that script in NEW mode. Post another while it serves, and the serving
commit runs again in UPDATE mode to prepare; once it says ready, the new commit
runs. Those assertions never skip.

The second is whatever one particular application does once applied — a page
that answers, checks it reports on. Those come from the profile and skip when it
does not describe them, which is what lets this suite point at any application
rather than one.

Three applies in a row, because the contract has three answers. The first, with
nothing serving, launches at once. The second, with the first serving, launches
a preparer and tells it what is coming; the third, with the second pending, is
refused. Then the preparer says ready and shuts down for real, the timer's next
look launches the second version, and the account says so.

The endpoint is `https://apply.{domain}/v1/commits`, derived from the domain. So
this stage uses the same route an operator would, rather than looking the API up
with the rescue key — a shortcut that would test a path nobody else can take.
"""

import json
import urllib.parse

import pytest
from harness import await_resolvable, fetch, head_sha, poll, post_json

from enclavize.aws import apigw
from enclavize.aws import s3 as s3mod
from enclavize.aws import scheduler as schedmod
from enclavize.aws import ssm as ssmmod
from enclavize.logic import naming
from setup import config as setup_config

pytestmark = pytest.mark.e2e

SETUP_RESOURCES = setup_config.RESOURCES

KEY_ANSWERS_IN_A_ROW = 10


@pytest.fixture(scope="session")
def endpoint(profile, apply_api_key):
    """The apply endpoint, once it will actually answer.

    A key and a base path mapping both take a moment to reach the edge after
    the bring-up creates them, and until they have every request is refused as
    unauthorised. Without waiting, the first assertion of the run reads that
    refusal as the endpoint rejecting what it was sent.

    A malformed commit is the probe: it can never reach the state machine, and
    the answer that means "ready" — refused by the validator rather than by the
    key — is the very thing the first test asserts.

    One such answer is not enough. The key reaches API Gateway's nodes one by
    one, and for some minutes after the bring-up a request may land on a node
    that has it or on one that does not — so the first 400 can be followed by
    a 403 on the very next call. Several in a row is the key being everywhere.
    """
    url = "https://{}/{}/{}".format(
        naming.apply_host(profile.domain), setup_config.APPLY_STAGE, setup_config.APPLY_API_PATH
    )

    def everywhere():
        return all(post_json(url, {"commit": "not-a-sha"}, api_key=apply_api_key)[0] == 400
                   for _ in range(KEY_ANSWERS_IN_A_ROW))

    poll(everywhere, timeout=profile.timeout("apply"), interval=10,
         what=f"{url} to accept its own API key from every node")
    return url


def parameter(rescue, name):
    value = ssmmod.try_get_parameter(rescue.client("ssm"), name)
    return json.loads(value) if value else None


def current_version(rescue):
    return parameter(rescue, SETUP_RESOURCES.apply_current_param)


def pending_version(rescue):
    return parameter(rescue, SETUP_RESOURCES.apply_pending_param)


def ready_word(rescue):
    return ssmmod.try_get_parameter(rescue.client("ssm"), SETUP_RESOURCES.apply_ready_param)


def record_at(rescue, account_id, key):
    bucket = naming.dashboard_bucket_name(account_id)
    return json.loads(s3mod.get_bytes(rescue.client("s3"), bucket=bucket, key=key))


def instance(rescue, instance_id):
    return rescue.client("ec2").describe_instances(
        InstanceIds=[instance_id]
    )["Reservations"][0]["Instances"][0]


def user_data_of(rescue, instance_id) -> str:
    import base64
    encoded = rescue.client("ec2").describe_instance_attribute(
        InstanceId=instance_id, Attribute="userData"
    )["UserData"].get("Value", "")
    return base64.b64decode(encoded).decode() if encoded else ""


# --- what the edge refuses ------------------------------------------------
#
# Cheap: neither reaches the state machine, so neither launches an instance.


def test_a_malformed_commit_is_refused_at_the_edge(endpoint, apply_api_key):
    """It ends up inside a shell command on the instance, so it is checked by a
    request validator before it can get that far."""
    status, _ = post_json(endpoint, {"commit": "not-a-sha"}, api_key=apply_api_key)
    assert status == 400


def test_an_unknown_key_is_refused(endpoint):
    status, _ = post_json(endpoint, {"commit": "a" * 40}, api_key="wrong" * 8)
    assert status == 403


def test_extra_fields_are_refused(endpoint, apply_api_key):
    """additionalProperties is false, so nothing rides along into the workflow."""
    status, _ = post_json(
        endpoint, {"commit": "a" * 40, "extra": "x"}, api_key=apply_api_key
    )
    assert status == 400


# --- the first apply: nothing serving, so it launches at once --------------


@pytest.fixture(scope="session")
def applied(profile, endpoint, apply_api_key):
    """The first apply of this cycle: the commit the profile names, or the head."""
    commit = head_sha(profile.app.repo, profile.app.ref)
    status, body = post_json(endpoint, {"commit": commit}, api_key=apply_api_key)
    assert status == 200, f"apply returned {status}: {body}"
    return {"commit": commit, "body": body}


@pytest.fixture(scope="session")
def first_record_key(applied, rescue):
    """Where the first apply was recorded, read while it is still what the
    account says is serving — the parameter moves on at the switch."""
    return current_version(rescue)["recordKey"]


def test_the_first_apply_launches_at_once(applied):
    """Nobody to prepare. It answers immediately rather than waiting: an
    Express workflow tops out at five minutes and API Gateway's integration at
    29 seconds, while running a real setup.sh takes longer than both."""
    body = applied["body"]
    assert body["status"] == "launched"
    assert body["commit"] == applied["commit"]
    assert body["instanceId"].startswith("i-")


def test_the_first_instance_is_told_it_is_new(applied, rescue):
    script = user_data_of(rescue, applied["body"]["instanceId"])
    assert "export ENCLAVIZE_MODE=NEW" in script
    assert "ENCLAVIZE_NEXT_COMMIT" not in script
    assert f"git checkout {applied['commit']}" in script


def test_the_account_records_what_is_serving(applied, rescue):
    """Written the moment the launch returns, not once the instance is up:
    what is serving is what the next apply's preparer will be told about."""
    serving = current_version(rescue)
    assert serving["commit"] == applied["commit"]
    assert serving["instanceId"] == applied["body"]["instanceId"]
    assert serving["recordKey"].startswith(naming.APPLIES_PREFIX)
    assert serving["since"] and serving["startedAt"]
    assert pending_version(rescue) is None


def test_the_apply_is_recorded_for_the_dashboard(applied, rescue, account_id):
    """The only trace of an apply that anyone outside can see, and the same
    object the API answered with."""
    record = record_at(rescue, account_id, current_version(rescue)["recordKey"])
    assert record == applied["body"]
    assert record["status"] == "launched"


def test_the_dashboard_can_reach_that_record_with_no_credentials(applied, rescue, profile):
    """The page is static and cannot list a bucket, so the state machine leaves
    it an index. Read over HTTPS the way a browser does, because that is the
    only path anyone outside the account has — the listing above is not one.
    """
    host = naming.dashboard_host(profile.domain)
    key = current_version(rescue)["recordKey"]

    def indexed():
        code, body = fetch(f"https://{host}/{naming.APPLIES_MANIFEST_KEY}")
        if code != 200:
            return None
        months = json.loads(body).get("months", [])
        if not months:
            return None
        # This apply happened moments ago, so its month is the newest there is.
        code, body = fetch(f"https://{host}/{max(months)}")
        if code != 200:
            return None
        shard = json.loads(body)
        return shard if key in shard.get("applies", []) else None

    shard = poll(indexed, timeout=180, interval=10,
                 what=f"https://{host}/{naming.APPLIES_MANIFEST_KEY} to index this apply")
    assert shard.get("truncated") is False, f"{shard['month']} was listed only in part"
    # Keys and nothing else: the page is public, and a listing's ETags and
    # storage classes are noise to anyone reading it.
    assert all(isinstance(k, str) for k in shard["applies"]), shard["applies"]
    code, body = fetch(f"https://{host}/{key}")
    assert code == 200
    assert json.loads(body)["status"] == "launched"


def test_the_instance_carries_the_bounded_role(applied, rescue):
    """Not the admin role: the boundary is the whole reason an applied commit
    can build freely without being able to touch the enclave."""
    found = instance(rescue, applied["body"]["instanceId"])
    profile_arn = found.get("IamInstanceProfile", {}).get("Arn", "")
    assert profile_arn.endswith(f"/{SETUP_RESOURCES.apply_role}"), profile_arn


# --- what one particular application does, while version one serves --------
#
# Optional. Absent from the profile, these skip and the contract above still
# stands — which is what makes the suite usable against any application. Here
# rather than at the end, because the version they ask about is replaced
# below and its answers go with it.


def test_the_application_answers(profile, applied):
    if not profile.app.url:
        pytest.skip("profile sets no app.url; enclavize's own contract is checked above")
    # The name is claimed by the commit being applied, so it does not exist when
    # this starts. Asking a caching resolver now would fix "no such host" in
    # front of it for as long as the zone says, which can outlast the wait.
    await_resolvable(urllib.parse.urlparse(profile.app.url).hostname,
                     domain=profile.domain, timeout=profile.timeout("apply"))
    poll(
        lambda: fetch(profile.app.url)[0] == 200,
        timeout=profile.timeout("apply"), interval=15,
        what=f"{profile.app.url} to answer",
    )


def results_for(profile, commit):
    """The application's own checks, from the version that ran `commit`.

    Holds out for the right version where the application names one. An
    application that replaces itself keeps serving the previous version's
    answers until the new one is ready, and those would satisfy this at once —
    reporting a pass for work that had not run.
    """
    def reported():
        code, body = fetch(profile.app.results_url)
        if code != 200:
            return None
        found = json.loads(body)
        # `commit` is optional in the contract. Where an application names the
        # commit behind its results, this holds out for the right ones.
        if found.get("commit") and found["commit"] != commit:
            return None
        return found

    return poll(
        reported, timeout=profile.timeout("apply"), interval=15,
        what=f"{profile.app.results_url} to report on {commit[:12]}",
    )


def assert_checks_passed(results):
    failed = [p for p in results.get("probes", []) if p.get("verdict") != "ok"]
    assert not failed, "the application's own checks failed:\n" + "\n".join(
        f"  {p.get('verdict')}  {p.get('name')} (expected {p.get('expected')}): {p.get('detail')}"
        for p in failed
    )
    assert results.get("ok") is True


def test_the_application_reports_its_own_checks_passing(profile, applied):
    """For an application that probes the permission boundary from inside the
    sealed account, this is the only place IAM itself answers. Everywhere else
    the boundary is asserted against a policy document — which says what should
    happen, not what did."""
    if not profile.app.results_url:
        pytest.skip("profile sets no app.resultsUrl")
    assert_checks_passed(results_for(profile, applied["commit"]))


# --- the second apply: something serving, so a preparer goes first ----------


@pytest.fixture(scope="session")
def preparing(applied, endpoint, apply_api_key, profile):
    """Apply again while the first version is serving — the next commit where
    the profile names one, so a different version arrives, and the same one
    again otherwise."""
    commit = head_sha(profile.app.repo, profile.app.next_ref) if profile.app.next_ref else applied["commit"]
    status, body = post_json(endpoint, {"commit": commit}, api_key=apply_api_key)
    assert status == 200, f"second apply returned {status}: {body}"
    return {"commit": commit, "body": body}


def test_a_later_apply_launches_a_preparer_rather_than_the_commit(preparing, applied):
    body = preparing["body"]
    assert body["status"] == "preparing"
    assert body["commit"] == preparing["commit"]
    assert body["previous"] == applied["commit"]
    assert body["preparerId"].startswith("i-")
    assert body["preparerId"] != applied["body"]["instanceId"]


def test_the_preparer_runs_the_serving_commit_and_is_told_what_is_coming(preparing, applied, rescue):
    """The serving version being given the chance to prepare: checked out at
    the commit already serving, in UPDATE mode, with the new one named."""
    script = user_data_of(rescue, preparing["body"]["preparerId"])
    assert f"git checkout {applied['commit']}" in script
    assert "export ENCLAVIZE_MODE=UPDATE" in script
    assert f"export ENCLAVIZE_NEXT_COMMIT={preparing['commit']}" in script

    found = instance(rescue, preparing["body"]["preparerId"])
    tags = {t["Key"]: t["Value"] for t in found.get("Tags", [])}
    assert tags[naming.COMMIT_TAG] == applied["commit"]
    assert tags[naming.PREPARING_FOR_TAG] == preparing["commit"]
    assert found.get("IamInstanceProfile", {}).get("Arn", "").endswith(f"/{SETUP_RESOURCES.apply_role}")


def test_the_account_says_what_is_pending_and_what_it_will_replace(preparing, applied, rescue):
    pending = pending_version(rescue)
    assert pending["commit"] == preparing["commit"]
    assert pending["recordKey"].endswith(f"_{preparing['commit']}.json")
    assert pending["previous"]["commit"] == applied["commit"]
    assert pending["previous"]["instanceId"] == applied["body"]["instanceId"]
    # Still serving: nothing changes until the preparer has spoken.
    assert current_version(rescue)["instanceId"] == applied["body"]["instanceId"]


def test_the_timer_is_set_to_look_every_few_minutes(preparing, rescue):
    schedule = schedmod.get_schedule(rescue.client("scheduler"), SETUP_RESOURCES.apply_check_schedule)
    assert schedule, "no schedule was created"
    assert schedule["ScheduleExpression"] == (
        f"rate({setup_config.PREPARE_CHECK_INTERVAL_MINUTES} minutes)"
    )
    assert schedule["Target"]["Arn"].endswith(
        f":stateMachine:{SETUP_RESOURCES.apply_check_state_machine}"
    )


def test_a_third_apply_is_refused_while_one_is_preparing(preparing, endpoint, apply_api_key):
    status, body = post_json(endpoint, {"commit": preparing["commit"]}, api_key=apply_api_key)
    assert status == 409, body
    assert body["error"] == apigw.IN_FLIGHT_ERROR


# --- the preparer speaks, the timer looks, the second version goes in -------


@pytest.fixture(scope="session")
def switched(preparing, applied, rescue, profile):
    """Wait for the whole handover. Nothing is simulated: the preparer says
    ready and shuts itself down, and the timer the second apply set is what
    starts the check that launches the new commit."""
    def replaced():
        found = current_version(rescue)
        return found if found and found["commit"] == preparing["commit"] else None

    check_wait = setup_config.PREPARE_CHECK_INTERVAL_MINUTES * 60
    return poll(replaced, timeout=profile.timeout("apply") + check_wait, interval=30,
                what=f"{SETUP_RESOURCES.apply_current_param} to name {preparing['commit'][:12]}")


def test_the_preparer_spoke_and_then_went(switched, preparing, rescue):
    """It was launched to terminate on shutdown; the application's last act in
    UPDATE mode is to shut down. Whichever came first, the check found nothing
    to stop."""
    state = instance(rescue, preparing["body"]["preparerId"])["State"]["Name"]
    assert state in ("shutting-down", "terminated"), state


def test_the_second_version_was_launched_as_new(switched, preparing, rescue):
    assert switched["instanceId"].startswith("i-")
    assert switched["instanceId"] != preparing["body"]["preparerId"]
    script = user_data_of(rescue, switched["instanceId"])
    assert f"git checkout {preparing['commit']}" in script
    assert "export ENCLAVIZE_MODE=NEW" in script


def test_the_timer_and_the_word_went_with_the_switch(switched, rescue):
    assert schedmod.get_schedule(rescue.client("scheduler"),
                                 SETUP_RESOURCES.apply_check_schedule) is None
    assert pending_version(rescue) is None
    assert ready_word(rescue) is None


def test_the_records_say_what_became_of_each_version(switched, first_record_key, preparing,
                                                     applied, rescue, account_id):
    """The records are the check's last act, after the new version is written
    down as serving — so they are waited for rather than read the instant the
    switch shows in the parameter."""
    def retired():
        found = record_at(rescue, account_id, first_record_key)
        return found if found["status"] == "retired" else None

    old = poll(retired, timeout=120, interval=5, what="the first version's record to say retired")
    new = record_at(rescue, account_id, switched["recordKey"])
    assert old["commit"] == applied["commit"]
    assert old["replacedBy"] == preparing["commit"]
    assert new["status"] == "launched"
    assert new["commit"] == preparing["commit"]
    assert new["instanceId"] == switched["instanceId"]
    assert new["previous"] == applied["commit"]


def test_the_check_ran_from_the_timer_and_not_from_anyone(switched, rescue):
    """The switch's only trace is the check machine's run, which is why the
    machine is Standard. It was started by the timer's role, with no input."""
    sfn = rescue.client("stepfunctions")
    arn = next(m["stateMachineArn"] for m in sfn.list_state_machines()["stateMachines"]
               if m["name"] == SETUP_RESOURCES.apply_check_state_machine)
    executions = sfn.list_executions(stateMachineArn=arn, statusFilter="SUCCEEDED")["executions"]
    assert executions, "no successful run of the check machine"
    inputs = {json.loads(sfn.describe_execution(executionArn=e["executionArn"])["input"] or "{}") == {}
              for e in executions}
    assert inputs == {True}


# --- and once version two has taken over -----------------------------------


def test_the_version_serving_is_the_one_applied_second(profile, switched, preparing):
    """From outside, with no credentials: what answers at the application's
    URL is the commit the second apply named — and its checks pass too, this
    time with a version to have replaced."""
    if not profile.app.results_url:
        pytest.skip("profile sets no app.resultsUrl")
    results = results_for(profile, preparing["commit"])
    assert results.get("commit") == preparing["commit"]
    assert_checks_passed(results)
