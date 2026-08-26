"""Stage 3: apply a commit.

Two layers, kept apart on purpose.

The first is enclavize's own contract, and it holds for *any* application: a
repository with an executable setup.sh at its root. Post a commit, an instance
runs that script. Those assertions never skip.

The second is whatever one particular application does once applied — a page
that answers, checks it reports on. Those come from the profile and skip when it
does not describe them, which is what lets this suite point at any application
rather than one.

The endpoint is `https://apply.{domain}/v1/commits`, derived from the domain. So
this stage uses the same route an operator would, rather than looking the API up
with the rescue key — a shortcut that would test a path nobody else can take.
"""

import json

import pytest
from harness import fetch, head_sha, poll, post_json

from enclavize.aws import s3 as s3mod
from enclavize.logic import naming
from setup import config as setup_config

pytestmark = pytest.mark.e2e

SETUP_RESOURCES = setup_config.RESOURCES


@pytest.fixture(scope="session")
def endpoint(profile):
    return "https://{}/{}/{}".format(
        naming.apply_host(profile.domain), setup_config.APPLY_STAGE, setup_config.APPLY_API_PATH
    )


@pytest.fixture(scope="session")
def applied(profile, endpoint, apply_api_key):
    """Apply the application's current head, once."""
    commit = head_sha(profile.app.repo, profile.app.ref)
    status, body = post_json(endpoint, {"commit": commit}, api_key=apply_api_key)
    assert status == 200, f"apply returned {status}: {body}"
    return {"commit": commit, "body": body}


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


# --- enclavize's contract, for any application ----------------------------


def test_applying_a_commit_launches_an_instance(applied):
    """It answers immediately rather than waiting: an Express workflow tops out
    at five minutes and API Gateway's integration at 29 seconds, while running a
    real setup.sh takes longer than both."""
    body = applied["body"]
    assert body["status"] == "launched"
    assert body["commit"] == applied["commit"]
    assert body["instanceId"].startswith("i-")


def test_the_apply_is_recorded_for_the_dashboard(applied, rescue, account_id):
    """The only trace of an apply that anyone outside can see."""
    bucket = naming.dashboard_bucket_name(account_id)
    key = f"applies/{applied['commit']}.json"
    found = poll(
        lambda: s3mod.object_exists(rescue.client("s3"), bucket=bucket, key=key),
        timeout=120, interval=10, what=f"s3://{bucket}/{key}",
    )
    assert found
    record = json.loads(s3mod.get_bytes(rescue.client("s3"), bucket=bucket, key=key))
    assert record["commit"] == applied["commit"]
    assert record["instanceId"] == applied["body"]["instanceId"]


def test_the_instance_carries_the_bounded_role(applied, rescue):
    """Not the admin role: the boundary is the whole reason an applied commit
    can build freely without being able to touch the enclave."""
    instance = rescue.client("ec2").describe_instances(
        InstanceIds=[applied["body"]["instanceId"]]
    )["Reservations"][0]["Instances"][0]
    profile_arn = instance.get("IamInstanceProfile", {}).get("Arn", "")
    assert profile_arn.endswith(f"/{SETUP_RESOURCES.apply_role}"), profile_arn


# --- what one particular application does ---------------------------------
#
# Optional. Absent from the profile, these skip and the contract above still
# stands — which is what makes the suite usable against any application.


def test_the_application_answers(profile):
    if not profile.app.url:
        pytest.skip("profile sets no app.url; enclavize's own contract is checked above")
    poll(
        lambda: fetch(profile.app.url)[0] == 200,
        timeout=profile.timeout("apply"), interval=15,
        what=f"{profile.app.url} to answer",
    )


def test_the_application_reports_its_own_checks_passing(profile):
    """For an application that probes the permission boundary from inside the
    sealed account, this is the only place IAM itself answers. Everywhere else
    the boundary is asserted against a policy document — which says what should
    happen, not what did.
    """
    if not profile.app.results_url:
        pytest.skip("profile sets no app.resultsUrl")

    body = poll(
        lambda: (lambda r: r[1] if r[0] == 200 else None)(fetch(profile.app.results_url)),
        timeout=profile.timeout("apply"), interval=15,
        what=f"{profile.app.results_url} to answer",
    )
    results = json.loads(body)

    failed = [p for p in results.get("probes", []) if p.get("verdict") != "ok"]
    assert not failed, "the application's own checks failed:\n" + "\n".join(
        f"  {p.get('verdict')}  {p.get('name')} (expected {p.get('expected')}): {p.get('detail')}"
        for p in failed
    )
    assert results.get("ok") is True
