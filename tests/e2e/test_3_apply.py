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
import urllib.parse

import pytest
from harness import await_resolvable, fetch, head_sha, poll, post_json

from enclavize.aws import s3 as s3mod
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


def keys_under(s3, bucket: str, prefix: str) -> list:
    pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
    return [obj["Key"] for page in pages for obj in page.get("Contents", [])]


def test_the_apply_is_recorded_for_the_dashboard(applied, rescue, account_id):
    """The only trace of an apply that anyone outside can see.

    Waits for a record naming *this* execution rather than merely for one to
    exist. The key carries the time, so applying the same commit twice leaves
    two records — and the instance is what tells them apart.
    """
    bucket = naming.dashboard_bucket_name(account_id)
    s3 = rescue.client("s3")

    def recorded():
        for key in keys_under(s3, bucket, naming.APPLIES_PREFIX):
            if not key.endswith(f"_{applied['commit']}.json"):
                continue
            found = json.loads(s3mod.get_bytes(s3, bucket=bucket, key=key))
            if found.get("instanceId") == applied["body"]["instanceId"]:
                return found
        return None

    record = poll(recorded, timeout=120, interval=10,
                  what=f"a record under s3://{bucket}/{naming.APPLIES_PREFIX} naming this instance")
    assert record["commit"] == applied["commit"]


def test_the_dashboard_can_reach_that_record_with_no_credentials(applied, profile):
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
        return shard if any(k.endswith(f"_{applied['commit']}.json") for k in keys) else None

    shard = poll(indexed, timeout=180, interval=10,
                 what=f"https://{host}/{naming.APPLIES_MANIFEST_KEY} to index this apply")
    assert not shard.get("truncated"), f"{shard['month']} was listed only in part"


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


def test_the_application_reports_its_own_checks_passing(profile, applied):
    """For an application that probes the permission boundary from inside the
    sealed account, this is the only place IAM itself answers. Everywhere else
    the boundary is asserted against a policy document — which says what should
    happen, not what did.

    Waits for results the commit just applied produced. An application that
    replaces itself keeps serving the previous deploy's answers until the new
    one is ready, and those would satisfy this at once — reporting a pass for
    work that had not run.
    """
    if not profile.app.results_url:
        pytest.skip("profile sets no app.resultsUrl")

    def reported():
        code, body = fetch(profile.app.results_url)
        if code != 200:
            return None
        found = json.loads(body)
        # `commit` is optional in the contract. Where an application names the
        # commit behind its results, this holds out for the right ones.
        if found.get("commit") and found["commit"] != applied["commit"]:
            return None
        return found

    results = poll(
        reported, timeout=profile.timeout("apply"), interval=15,
        what=f"{profile.app.results_url} to report on {applied['commit'][:12]}",
    )

    failed = [p for p in results.get("probes", []) if p.get("verdict") != "ok"]
    assert not failed, "the application's own checks failed:\n" + "\n".join(
        f"  {p.get('verdict')}  {p.get('name')} (expected {p.get('expected')}): {p.get('detail')}"
        for p in failed
    )
    assert results.get("ok") is True
