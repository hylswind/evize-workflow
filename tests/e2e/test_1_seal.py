"""Stage 1: drive the real workflow, and check what it signed.

This is the stage the whole project rests on. `gh attestation verify
--signer-workflow` against a reusable workflow cannot be exercised anywhere but
here — no fake reproduces a Sigstore certificate — and if it does not hold, a
statement proves nothing at all.

Everything is checked with the rescue root key, which is itself evidence: every
one of these calls happens after the console has been locked, and they all
succeed, because a sign-in policy governs interactive sign-in and never a signed
API request.
"""

import datetime
import json
import os
import subprocess

import pytest
from botocore.exceptions import ClientError
from harness import PREDICATE_TYPE, STATE_FILE, gh, poll, repo_id, verify_attestation

from enclavize.aws import signin as signinmod
from workflow import config as workflow_config

pytestmark = pytest.mark.e2e

RESOURCES = workflow_config.RESOURCES


def newest_run_after(caller, workflow, since):
    """gh workflow run reports nothing about the run it started, so it has to be
    found: the newest run of that workflow created after we dispatched."""
    runs = gh("run", "list", "--repo", caller, "--workflow", workflow,
              "--limit", "20", "--json", "databaseId,createdAt", parse_json=True) or []
    fresh = [r for r in runs
             if datetime.datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00")) >= since]
    return max(fresh, key=lambda r: r["createdAt"])["databaseId"] if fresh else None


@pytest.fixture(scope="session")
def sealed(profile, caller, account_id, tmp_path_factory):
    """Dispatch, wait, and download. One run per session.

    ENCLAVIZE_E2E_RUN_ID attaches to a run that already happened, so the
    assertions can be re-run without spending another cycle.
    """
    existing = os.environ.get("ENCLAVIZE_E2E_RUN_ID")
    start = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 600

    if existing:
        run_id = int(existing)
    else:
        since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=30)
        gh("workflow", "run", profile.caller_workflow, "--repo", profile.caller,
           "-f", f"domain={profile.domain}",
           "-f", f"start={start}",
           "-f", f"repo={profile.app.repo}",
           "-f", "bypass_event_check=true",
           "-f", f"bypass_domain_transfer={str(profile.bypass_domain_transfer).lower()}")
        run_id = poll(
            lambda: newest_run_after(profile.caller, profile.caller_workflow, since),
            timeout=120, interval=5, what="the dispatched run to appear",
        )
        print(f"\nrun {run_id}: https://github.com/{profile.caller}/actions/runs/{run_id}")

    def finished():
        view = gh("run", "view", str(run_id), "--repo", profile.caller,
                  "--json", "status,conclusion", parse_json=True)
        return view if view["status"] == "completed" else None

    # Polled rather than `gh run watch`, so a timeout can say what it was
    # waiting on instead of dying inside another program's progress display.
    view = poll(finished, timeout=profile.timeout("seal"), interval=30,
                what=f"run {run_id} to finish")

    artifacts = tmp_path_factory.mktemp("run")
    gh("run", "download", str(run_id), "--repo", profile.caller,
       "-n", "enclavize-statement", "-D", str(artifacts), check=False)
    gh("run", "download", str(run_id), "--repo", profile.caller,
       "-n", "enclavize-console", "-D", str(artifacts), check=False)

    statement_path = artifacts / "statement.json"
    statement = json.loads(statement_path.read_text()) if statement_path.exists() else None

    STATE_FILE.write_text(json.dumps({
        "runId": run_id,
        "caller": profile.caller,
        "signerWorkflow": caller.signer_workflow,
        "mode": profile.transfer,
        "accountId": account_id,
        "start": start,
        "statement": statement,
    }, indent=2) + "\n")

    return {
        "run_id": run_id, "conclusion": view["conclusion"], "dir": artifacts,
        "statement_path": statement_path, "statement": statement, "start": start,
    }


# --- the run itself -------------------------------------------------------


def test_the_run_succeeded(sealed, profile):
    assert sealed["conclusion"] == "success", (
        f"see https://github.com/{profile.caller}/actions/runs/{sealed['run_id']}"
    )


# --- the statement --------------------------------------------------------


def test_the_statement_describes_this_account_and_this_app(sealed, profile, account_id):
    statement = sealed["statement"]
    assert statement is not None, "no enclavize-statement artifact was produced"
    assert statement["accountID"] == account_id
    assert statement["domain"] == profile.domain
    assert statement["start"] == sealed["start"]
    assert statement["holdSeconds"] == workflow_config.HOLD_SECONDS


def test_the_statement_names_the_app_by_id_not_by_name(sealed, profile):
    """A repository name can be reassigned to somebody else; its id cannot."""
    assert sealed["statement"]["repoID"] == repo_id(profile.app.repo)


def test_the_bypasses_are_recorded_honestly(sealed, profile):
    """The suite always bypasses the audit — a rescue root key means two
    CreateAccessKey events and the audit permits exactly one. So the thing worth
    asserting is that the statement says so, and is marked debug because of it.
    """
    statement = sealed["statement"]
    assert statement["bypasses"]["eventCheck"] is True
    assert statement["bypasses"]["domainTransfer"] is profile.bypass_domain_transfer
    assert statement["debug"] is True


# --- the signature, which is the point ------------------------------------


def test_the_attestation_verifies_against_the_signer_workflow(sealed, profile, caller):
    """The trust anchor. The attestation is signed by the reusable workflow
    rather than by the repo that called it, which is what lets one verifier
    cover every account sealed this way."""
    assert verify_attestation(
        sealed["statement_path"], caller=profile.caller,
        signer_workflow=caller.signer_workflow,
    )


def test_a_different_signer_workflow_is_rejected(sealed, profile, caller):
    """Otherwise the check above proves nothing: a verify that passes for
    anything is not a verify."""
    impostor = caller.signer_workflow.replace(".github/workflows/", ".github/workflows/not-")
    assert not verify_attestation(
        sealed["statement_path"], caller=profile.caller, signer_workflow=impostor,
    )


def test_the_wrong_predicate_type_is_rejected(sealed, profile, caller):
    """The default is SLSA provenance; this predicate is enclavize's own."""
    assert PREDICATE_TYPE != "https://slsa.dev/provenance/v1"
    assert not verify_attestation(
        sealed["statement_path"], caller=profile.caller,
        signer_workflow=caller.signer_workflow,
        predicate_type="https://slsa.dev/provenance/v1",
    )


# --- the console credentials ----------------------------------------------


def test_the_console_archive_needs_its_password(sealed):
    """7z with an empty password writes a readable archive, and this one is a
    public artifact holding a console password."""
    password = os.environ.get("ENCLAVIZE_CONSOLE_ZIP_PASSWORD")
    if not password:
        pytest.skip("ENCLAVIZE_CONSOLE_ZIP_PASSWORD not set")
    archive = sealed["dir"] / "console.7z"
    assert archive.exists(), "no enclavize-console artifact was produced"

    def sevenzip(*args):
        return subprocess.run(("7z",) + args, capture_output=True, text=True).returncode

    assert sevenzip("t", "-p", str(archive)) != 0, "the archive opened with no password"
    assert sevenzip("t", f"-p{password}", str(archive)) == 0

    out = sealed["dir"] / "console"
    subprocess.run(("7z", "x", f"-p{password}", f"-o{out}", "-y", str(archive)),
                   capture_output=True, check=True)
    credentials = json.loads((out / "console.json").read_text())
    assert credentials["accountId"] and credentials["userName"] and credentials["password"]
    assert credentials["signInUrl"].startswith(f"https://{credentials['accountId']}.")


# --- what the account looks like now --------------------------------------


def test_the_root_key_the_workflow_was_given_is_gone(rescue, profile, caller_arn):
    """The run deletes the key it was handed. Anything else would outlive the
    seal, which is exactly what the audit exists to catch.

    Only root can see this. `list_access_keys` from any other identity silently
    answers about the *caller* instead — a wrong answer rather than an error —
    so from an IAM user this can only be checked by hand.
    """
    iam = rescue.client("iam")
    if not caller_arn.endswith(":root"):
        assert iam.get_account_summary()["SummaryMap"].get("AccountAccessKeysPresent"), (
            "root has no access key at all — if your way back in was one, it is gone"
        )
        pytest.skip(
            f"signed in as {caller_arn}: AWS offers no way to enumerate root's keys "
            "from another identity, and AccountAccessKeysPresent is a flag rather "
            "than a count. Check by hand that only your rescue key remains."
        )

    remaining = {k["AccessKeyId"] for k in iam.list_access_keys()["AccessKeyMetadata"]}
    assert len(remaining) == 1, f"expected only the rescue key, found {remaining}"
    if profile.rescue_key_id:
        assert remaining == {profile.rescue_key_id}


def test_the_identities_that_outlive_root_exist(rescue):
    iam = rescue.client("iam")
    iam.get_role(RoleName=RESOURCES.admin_role)
    iam.get_instance_profile(InstanceProfileName=RESOURCES.instance_profile())
    for user in (RESOURCES.event_reader_user, RESOURCES.starter_user, RESOURCES.console_user):
        iam.get_user(UserName=user)


def test_the_console_is_locked(rescue):
    statements = signinmod.list_statements(rescue.client("signin", region_name="us-east-1"))
    assert len(statements) == 1, f"expected exactly one sign-in statement, found {len(statements)}"


def test_the_lock_is_anchored_to_a_vpc_nothing_can_originate_from(rescue):
    vpcs = rescue.client("ec2").describe_vpcs(
        Filters=[{"Name": "tag:Name", "Values": [RESOURCES.signin_lock_vpc_tag]}]
    )["Vpcs"]
    assert len(vpcs) == 1
    assert vpcs[0]["CidrBlock"] == RESOURCES.signin_lock_vpc_cidr


def test_the_sign_in_lock_does_not_apply_to_signed_api_calls(rescue):
    """Stated outright because every other assertion in this file depends on it:
    the console is shut, and these calls still work. That asymmetry is what
    makes the lock safe to apply — and what makes the account recoverable."""
    assert rescue.client("sts").get_caller_identity()["Arn"].endswith(":root")


def test_the_account_was_handed_over(rescue):
    value = rescue.client("ssm").get_parameter(Name=RESOURCES.go_param)["Parameter"]["Value"]
    assert value == workflow_config.GO_VALUE


def test_the_account_holds_the_domain(rescue, profile):
    """In `real` mode this is the proof that accepting the transfer worked —
    the one path no isolated test can reach, since it needs a real pending
    transfer and moves a real domain when it succeeds."""
    domains = rescue.client("route53domains", region_name="us-east-1")
    held = {d["DomainName"].lower() for page in domains.get_paginator("list_domains").paginate()
            for d in page["Domains"]}
    assert profile.domain in held


def test_the_starter_still_exists_until_the_proof_lands(rescue):
    """It is deleted by the bring-up, not by the seal — the workflow still needs
    it to publish proof into the account after signing."""
    try:
        rescue.client("iam").get_user(UserName=RESOURCES.starter_user)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            pytest.skip("the bring-up has already retired the starter; stage 2 checks that")
        raise
