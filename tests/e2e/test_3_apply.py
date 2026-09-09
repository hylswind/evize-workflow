"""Stage 3: apply a commit, then apply it again.

Two layers, kept apart on purpose.

The first is enclavize's own contract, and it holds for *any* application: a
repository with an executable setup.sh at its root that answers on port 80 and
says it is ready at /healthz. Post a commit, an instance runs that script, and
once the load balancer sees it healthy the front door switches to it. Those
assertions never skip.

The second is whatever one particular application does once applied — a page
that answers, checks it reports on. Those come from the profile and skip when it
does not describe them, which is what lets this suite point at any application
rather than one.

Three applies in a row, because the contract has three answers. The first, with
nothing serving, switches at once. The second, with the first serving, is
scheduled and the serving version is told; the third, with the second pending,
is refused. Then the schedule fires for real — the delay is short enough to
wait out — and the second version replaces the first.

The endpoint is `https://apply.{domain}/v1/commits`, derived from the domain. So
this stage uses the same route an operator would, rather than looking the API up
with the rescue key — a shortcut that would test a path nobody else can take.
"""

import datetime
import json
import time
import urllib.parse

import pytest
from botocore.exceptions import ClientError
from harness import await_resolvable, fetch, head_sha, poll, post_json

from enclavize.aws import apigw
from enclavize.aws import elbv2 as elbmod
from enclavize.aws import s3 as s3mod
from enclavize.aws import scheduler as schedmod
from enclavize.aws import ssm as ssmmod
from enclavize.logic import naming
from setup import config as setup_config

pytestmark = pytest.mark.e2e

SETUP_RESOURCES = setup_config.RESOURCES


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
    """
    url = "https://{}/{}/{}".format(
        naming.apply_host(profile.domain), setup_config.APPLY_STAGE, setup_config.APPLY_API_PATH
    )
    poll(
        lambda: post_json(url, {"commit": "not-a-sha"}, api_key=apply_api_key)[0] == 400,
        timeout=profile.timeout("apply"), interval=10,
        what=f"{url} to accept its own API key",
    )
    return url


def current_version(rescue):
    value = ssmmod.try_get_parameter(rescue.client("ssm"), SETUP_RESOURCES.apply_current_param)
    return json.loads(value) if value else None


def pending_version(rescue):
    value = ssmmod.try_get_parameter(rescue.client("ssm"), SETUP_RESOURCES.apply_pending_param)
    return json.loads(value) if value else None


def record_at(rescue, account_id, key):
    bucket = naming.dashboard_bucket_name(account_id)
    return json.loads(s3mod.get_bytes(rescue.client("s3"), bucket=bucket, key=key))


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


# --- the first apply: nothing serving, so it switches at once --------------


@pytest.fixture(scope="session")
def applied(profile, endpoint, apply_api_key):
    """The first apply of this cycle: the commit the profile names, or the head."""
    commit = head_sha(profile.app.repo, profile.app.ref)
    status, body = post_json(endpoint, {"commit": commit}, api_key=apply_api_key)
    assert status == 200, f"apply returned {status}: {body}"
    return {"commit": commit, "body": body}


def test_the_first_apply_switches_at_once(applied):
    """Nobody to warn and nothing to protect. It answers as soon as the switch
    has started rather than waiting for it: the instance has to boot, run
    setup.sh and pass its health checks first."""
    body = applied["body"]
    assert body["status"] == "switching"
    assert body["commit"] == applied["commit"]
    assert "instanceId" not in body, "the instance is the switch's to launch, not the answer's"


@pytest.fixture(scope="session")
def serving(applied, rescue, profile):
    """Block until the first version is serving: the account says so itself."""
    def switched_in():
        found = current_version(rescue)
        return found if found and found["commit"] == applied["commit"] else None

    return poll(switched_in, timeout=profile.timeout("apply"), interval=15,
                what=f"{SETUP_RESOURCES.apply_current_param} to name {applied['commit'][:12]}")


def test_the_account_records_what_is_serving(serving, applied):
    assert serving["instanceId"].startswith("i-")
    assert serving["targetGroupArn"].startswith("arn:aws:elasticloadbalancing:")
    assert serving["recordKey"].startswith(naming.APPLIES_PREFIX)
    assert serving["since"]


def front_door_forwards_to(rescue) -> set:
    elbv2 = rescue.client("elbv2")
    balancer = elbmod.load_balancers_named(elbv2, SETUP_RESOURCES.prefix)[0]
    listener = [l for l in elbv2.describe_listeners(LoadBalancerArn=balancer["arn"])["Listeners"]
                if l["Port"] == 443][0]
    action = listener["DefaultActions"][0]
    if action["Type"] != "forward":
        return set()
    weighted = action.get("ForwardConfig", {}).get("TargetGroups", [])
    groups = {g["TargetGroupArn"] for g in weighted if g.get("Weight", 1) > 0}
    if action.get("TargetGroupArn"):
        groups.add(action["TargetGroupArn"])
    return groups


def test_the_front_door_forwards_only_to_the_serving_version(serving, rescue):
    """One listener change is the switch. Whatever is on the listener with
    weight is what the world reaches, so it has to be this and only this."""
    assert front_door_forwards_to(rescue) == {serving["targetGroupArn"]}
    health = rescue.client("elbv2").describe_target_health(
        TargetGroupArn=serving["targetGroupArn"]
    )["TargetHealthDescriptions"]
    assert [(h["Target"]["Id"], h["TargetHealth"]["State"]) for h in health] == [
        (serving["instanceId"], "healthy")
    ]


def test_the_health_check_answers_from_outside(serving, profile):
    """The same path the load balancer takes, from the other side of it."""
    code, _ = fetch(f"https://{profile.domain}{setup_config.HEALTH_PATH}")
    assert code == 200


def test_the_apply_is_recorded_for_the_dashboard(serving, applied, rescue, account_id):
    """The only trace of an apply that anyone outside can see, rewritten by the
    switch as it went: it now says the version is live, and which instance."""
    record = record_at(rescue, account_id, serving["recordKey"])
    assert record["commit"] == applied["commit"]
    assert record["status"] == "live"
    assert record["instanceId"] == serving["instanceId"]


def test_the_dashboard_can_reach_that_record_with_no_credentials(serving, applied, profile):
    """The page is static and cannot list a bucket, so the state machine leaves
    it an index. Read over HTTPS the way a browser does, because that is the
    only path anyone outside the account has — the listing above is not one.
    """
    host = naming.dashboard_host(profile.domain)

    def indexed():
        code, body = fetch(f"https://{host}/{naming.APPLIES_MANIFEST_KEY}")
        if code != 200:
            return None
        months = [entry["Key"] for entry in json.loads(body).get("months", [])]
        if not months:
            return None
        # This apply happened moments ago, so its month is the newest there is.
        code, body = fetch(f"https://{host}/{max(months)}")
        if code != 200:
            return None
        shard = json.loads(body)
        keys = [entry["Key"] for entry in shard.get("applies", [])]
        return shard if serving["recordKey"] in keys else None

    shard = poll(indexed, timeout=180, interval=10,
                 what=f"https://{host}/{naming.APPLIES_MANIFEST_KEY} to index this apply")
    assert not shard.get("truncated"), f"{shard['month']} was listed only in part"
    code, body = fetch(f"https://{host}/{serving['recordKey']}")
    assert code == 200
    assert json.loads(body)["status"] == "live"


def test_the_instance_carries_the_bounded_role(serving, rescue):
    """Not the admin role: the boundary is the whole reason an applied commit
    can build freely without being able to touch the enclave."""
    instance = rescue.client("ec2").describe_instances(
        InstanceIds=[serving["instanceId"]]
    )["Reservations"][0]["Instances"][0]
    profile_arn = instance.get("IamInstanceProfile", {}).get("Arn", "")
    assert profile_arn.endswith(f"/{SETUP_RESOURCES.apply_role}"), profile_arn
    # Reachable through the front door only.
    assert [g["GroupName"] for g in instance["SecurityGroups"]] == [SETUP_RESOURCES.app_sg]


# --- the second apply: something serving, so it waits ----------------------


@pytest.fixture(scope="session")
def scheduled(serving, endpoint, apply_api_key, applied, profile):
    """Apply again while the first version is serving — the next commit where
    the profile names one, so the switch has a different version to reach, and
    the same one again otherwise."""
    commit = head_sha(profile.app.repo, profile.app.next_ref) if profile.app.next_ref else applied["commit"]
    received = time.time()
    status, body = post_json(endpoint, {"commit": commit}, api_key=apply_api_key)
    assert status == 200, f"second apply returned {status}: {body}"
    return {"commit": commit, "body": body, "received": received}


def test_a_later_apply_is_scheduled_rather_than_switched(scheduled):
    body = scheduled["body"]
    assert body["status"] == "scheduled"
    switch_at = datetime.datetime.fromisoformat(body["switchAt"].replace("Z", "+00:00")).timestamp()
    expected = scheduled["received"] + setup_config.SWITCH_DELAY_SECONDS
    assert abs(switch_at - expected) < 120, (body["switchAt"], expected)


def test_the_serving_version_is_told_what_is_coming(scheduled, rescue):
    """The one channel an application has: a parameter it can read and not
    write, saying which commit and when."""
    pending = pending_version(rescue)
    assert pending == {"commit": scheduled["commit"], "switchAt": scheduled["body"]["switchAt"]}


def test_the_timer_is_set_to_fire_once(scheduled, rescue):
    schedule = schedmod.get_schedule(rescue.client("scheduler"), SETUP_RESOURCES.apply_switch_schedule)
    assert schedule, "no schedule was created"
    assert schedule["ActionAfterCompletion"] == "DELETE"
    assert schedule["ScheduleExpression"].startswith("at(")
    assert schedule["Target"]["Arn"].endswith(f":stateMachine:{SETUP_RESOURCES.apply_switch_state_machine}")


def test_a_third_apply_is_refused_while_one_is_pending(scheduled, endpoint, apply_api_key):
    status, body = post_json(endpoint, {"commit": scheduled["commit"]}, api_key=apply_api_key)
    assert status == 409, body
    assert body["error"] == apigw.IN_FLIGHT_ERROR


# --- the timer fires, and the second version replaces the first ------------


@pytest.fixture(scope="session")
def switched(scheduled, serving, rescue, profile):
    """Wait out the delay and the switch itself. Nothing is simulated: the
    schedule the second apply made is what starts it."""
    def replaced():
        found = current_version(rescue)
        return found if found and found["instanceId"] != serving["instanceId"] else None

    return poll(replaced, timeout=setup_config.SWITCH_DELAY_SECONDS + profile.timeout("apply"),
                interval=30, what="the scheduled switch to put a new instance in service")


def test_the_timer_went_once_it_had_fired(switched, rescue):
    assert schedmod.get_schedule(rescue.client("scheduler"),
                                 SETUP_RESOURCES.apply_switch_schedule) is None


def test_the_new_version_is_the_one_the_front_door_reaches(switched, rescue):
    assert front_door_forwards_to(rescue) == {switched["targetGroupArn"]}


def test_the_previous_version_was_retired(switched, serving, rescue):
    """Deregistered, drained, terminated, and its target group deleted — none
    of which an application has to do for itself any more."""
    ec2, elbv2 = rescue.client("ec2"), rescue.client("elbv2")

    def gone():
        state = ec2.describe_instances(InstanceIds=[serving["instanceId"]])["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state not in ("shutting-down", "terminated"):
            return None
        try:
            elbv2.describe_target_groups(TargetGroupArns=[serving["targetGroupArn"]])
            return None
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TargetGroupNotFound":
                raise
        return state

    assert poll(gone, timeout=300, interval=15, what="the previous version to be retired")
    assert pending_version(rescue) is None


def test_the_records_say_what_became_of_each_version(switched, serving, scheduled, rescue, account_id):
    old = record_at(rescue, account_id, serving["recordKey"])
    new = record_at(rescue, account_id, switched["recordKey"])
    assert old["status"] == "retired"
    assert new["status"] == "live"
    assert new["instanceId"] == switched["instanceId"]
    assert new["commit"] == scheduled["commit"]


def test_the_new_version_answers_through_the_front_door(switched, profile):
    code, _ = fetch(f"https://{profile.domain}{setup_config.HEALTH_PATH}")
    assert code == 200


# --- what one particular application does ---------------------------------
#
# Optional. Absent from the profile, these skip and the contract above still
# stands — which is what makes the suite usable against any application.


def test_the_application_answers(profile, serving):
    if not profile.app.url:
        pytest.skip("profile sets no app.url; enclavize's own contract is checked above")
    await_resolvable(urllib.parse.urlparse(profile.app.url).hostname,
                     domain=profile.domain, timeout=profile.timeout("apply"))
    poll(
        lambda: fetch(profile.app.url)[0] == 200,
        timeout=profile.timeout("apply"), interval=15,
        what=f"{profile.app.url} to answer",
    )


def results_for(profile, commit):
    """The application's own checks, from the version that ran `commit`.

    Holds out for the right version where the application names one. The
    front door only ever forwards to one version at a time, so the previous
    one's answers cannot linger — but the poll still starts before the switch
    has necessarily reached the version being asked about.
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


def test_the_application_reports_its_own_checks_passing(profile, serving, applied):
    """For an application that probes the permission boundary from inside the
    sealed account, this is the only place IAM itself answers. Everywhere else
    the boundary is asserted against a policy document — which says what should
    happen, not what did."""
    if not profile.app.results_url:
        pytest.skip("profile sets no app.resultsUrl")
    assert_checks_passed(results_for(profile, applied["commit"]))


def test_the_version_switched_to_is_the_one_applied_second(profile, switched, scheduled):
    """From outside, with no credentials: what answers at the domain is the
    commit the second apply named — and its checks pass too, this time with
    a version to have replaced."""
    if not profile.app.results_url:
        pytest.skip("profile sets no app.resultsUrl")
    results = results_for(profile, scheduled["commit"])
    assert results.get("commit") == scheduled["commit"]
    assert_checks_passed(results)
