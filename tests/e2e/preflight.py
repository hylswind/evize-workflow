"""Everything that can be checked before a run, checked before the run.

    ENCLAVIZE_E2E_PROFILE=tests/e2e/profiles/mine.yml \
    ENCLAVIZE_TEST_ACCOUNTS=111122223333 \
      python tests/e2e/preflight.py

Read-only, and worth its own command because the alternative is discovering a
missing input or a leftover role most of an hour into a two-hour cycle. It ends
by printing the exact `gh workflow run` it would issue, and what to set before
issuing it.

Nothing here is specific to a caller or an application: the caller is read from
its own workflow file, and every resource name comes from the production config.
"""

import argparse
import datetime
import os
import pathlib
import sys

import boto3

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from enclavize.aws import domains as domainsmod  # noqa: E402
from harness import (  # noqa: E402
    ProfileError,
    allowed_accounts,
    caller_problems,
    caller_workflow_text,
    derive_caller,
    gh,
    leftovers,
    load_profile,
    unfit_to_unseal,
)

OK, BAD, WARN = "  ok  ", " FAIL ", " warn "

SEAL_STEP = "seal the account"
"""The step that deletes the root key it was handed. Naming it is what lets a
run that got that far be told apart from one that failed before it."""


class Report:
    """Collects findings so every problem is reported, not just the first."""

    def __init__(self):
        self.failures = 0
        self.warnings = 0

    def ok(self, message):
        print(f"[{OK}] {message}")

    def bad(self, message):
        self.failures += 1
        print(f"[{BAD}] {message}")

    def warn(self, message):
        self.warnings += 1
        print(f"[{WARN}] {message}")

    def check(self, condition, good, bad):
        self.ok(good) if condition else self.bad(bad)
        return condition


def check_identity(report, region):
    """An allow-listed account, and credentials that can undo what a run does."""
    allowed = allowed_accounts()
    if not allowed:
        report.bad("ENCLAVIZE_TEST_ACCOUNTS is empty; refusing to look at any account")
        return None, ""

    identity = boto3.client("sts", region_name=region).get_caller_identity()
    account, arn = identity["Account"], identity["Arn"]

    if not report.check(
        account in allowed,
        f"account {account} is allow-listed",
        f"account {account} is NOT in ENCLAVIZE_TEST_ACCOUNTS",
    ):
        return None, arn

    problem = unfit_to_unseal(arn, region)
    if problem:
        report.bad(problem)
    else:
        report.ok(f"{arn} can unseal this account afterwards")
    return account, arn


def check_root_keys(report, session, profile, arn):
    """That root has a key for the workflow to spend, and one to get back in.

    AWS allows two access keys per user, root included, and the loop sits at
    that limit: one is handed to the workflow, which deletes it; the other is
    the way back in.

    How much of that is visible depends on who is asking. Only root can list
    root's keys — from any other identity there is no API for it at all, and
    `list_access_keys` quietly returns the *caller's* keys instead, which is a
    far worse answer than an error.
    """
    iam = session.client("iam")

    if arn.endswith(":root"):
        keys = iam.list_access_keys()["AccessKeyMetadata"]
        if not keys:
            report.bad("root has no access key; the workflow needs one and you need a way back in")
            return
        for key in keys:
            role = "rescue" if key["AccessKeyId"] == profile.rescue_key_id else "for the workflow"
            print(f"          {key['AccessKeyId']}  {key['CreateDate']:%Y-%m-%d %H:%M}  ({role})")
        if profile.rescue_key_id and profile.rescue_key_id not in {k["AccessKeyId"] for k in keys}:
            report.bad(f"the profile's rescueKeyId {profile.rescue_key_id} is not on this account")
            return
        if len(keys) == 1:
            report.warn("only one root key: mint the second and set ROOT_KEY_ID before dispatching")
        elif len(keys) == 2:
            report.ok("two root keys, which is the AWS maximum — one to spend, one to keep")
        else:
            report.bad(f"{len(keys)} root keys; expected at most two")
        return

    # Not root. AccountAccessKeysPresent is all AWS offers here, and it is a
    # presence flag rather than a count: it reads 1 whether root holds one key
    # or two, so it can only catch root having none at all.
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountAccessKeysPresent"):
        report.ok("root has at least one access key")
    else:
        report.bad(
            "root has no access key at all — the workflow needs one, and if your way "
            "back in was a root key it is gone too"
        )
    report.warn(
        f"signed in as {arn}, not root, so the root keys cannot be enumerated: AWS "
        "offers no API for it. Check by hand that ROOT_KEY_ID is the key you mean to "
        "spend, and that a second one exists as your way back in"
    )
    if profile.rescue_key_id:
        report.warn(
            "rescueKeyId is set but means nothing from a non-root identity; remove it "
            "from the profile unless you run this suite as root"
        )


def check_account_is_clean(report, session, profile, account):
    """That the last teardown finished.

    The same description the teardown reports against, so the two cannot
    disagree about whether a cycle may start — and in particular so a hosted
    zone the teardown deliberately preserved is not read here as a leftover.
    """
    remaining = leftovers(session, account, profile)
    if remaining:
        report.bad("the previous teardown did not finish — run unseal.py first:")
        for item in remaining:
            print(f"          - {item}")
    else:
        report.ok("account is clean; nothing left from a previous run")


def check_caller(report, profile, secrets):
    """Read the caller rather than assuming it, and say what is wrong with it."""
    try:
        caller = derive_caller(caller_workflow_text(profile))
    except (ProfileError, RuntimeError) as exc:
        report.bad(f"cannot read {profile.caller}'s {profile.caller_workflow}: {exc}")
        return None

    problems = caller_problems(caller)
    for problem in problems:
        report.bad(problem)
    if not problems:
        report.ok(f"{profile.caller} exposes the inputs and permissions this suite needs")

    report.ok(f"signs as {caller.signer_workflow}")
    if caller.pinned_to_a_commit:
        report.ok(f"pinned to {caller.ref}")
    else:
        report.warn(
            f"pinned to '{caller.ref}', a moving ref. Fine while developing; a proof "
            "meant to mean something needs a commit sha"
        )

    have = {s["name"] for s in secrets}
    missing = caller.secrets - have
    if missing:
        report.bad(f"{profile.caller} is missing secrets: {', '.join(sorted(missing))}")
    else:
        report.ok(f"all {len(caller.secrets)} secrets the caller passes down are set")
    return caller


def check_the_root_key_secret_is_not_spent(report, profile, secrets):
    """Whether ROOT_KEY_ID still names a key that exists.

    Its value cannot be read — GitHub secrets are write-only — but its age can,
    and that is enough. A run that reached the sealing step deleted whatever key
    it was handed, so a secret older than the last such run names a key that is
    already gone.

    This is the one part of the root-key picture visible from a non-root
    identity, and without it a spent cycle looks ready and dies on its first
    API call.
    """
    set_at = next((s["updatedAt"] for s in secrets if s["name"] == "ROOT_KEY_ID"), None)
    if not set_at:
        return

    runs = gh("run", "list", "--repo", profile.caller, "--workflow", profile.caller_workflow,
              "--limit", "20", "--json", "databaseId,createdAt", parse_json=True) or []
    for run in runs:
        # Newest first, and both stamps are UTC in the same format.
        if run["createdAt"] <= set_at:
            break
        jobs = gh("api", f"repos/{profile.caller}/actions/runs/{run['databaseId']}/jobs",
                  parse_json=True) or {}
        if any(step.get("name") == SEAL_STEP and step.get("conclusion") == "success"
               for job in jobs.get("jobs", []) for step in job.get("steps", [])):
            report.bad(
                f"ROOT_KEY_ID was set at {set_at}, and the run at {run['createdAt']} sealed "
                "the account — which deletes the root key it was given, so this secret now "
                "names a key that no longer exists.\n"
                "          Mint a new one with the credentials you kept back, then set "
                "ROOT_KEY_ID and ROOT_SECRET again:\n"
                "            aws iam create-access-key      # signed as root; an IAM user cannot"
            )
            return
    report.ok("ROOT_KEY_ID has not been spent by a later run")


def check_domain(report, session, profile):
    """Membership, not an error code: `real` needs the domain elsewhere and
    `bypass` needs it here, and getting this wrong wastes a whole cycle."""
    domains = session.client("route53domains", region_name=domainsmod.REGION)
    held = {d["DomainName"].lower() for page in domains.get_paginator("list_domains").paginate()
            for d in page["Domains"]}
    here = profile.domain in held

    if profile.transfer == "real":
        report.check(
            not here,
            f"{profile.domain} is not in this account yet, as 'real' expects",
            f"{profile.domain} is ALREADY in this account; use transfer: bypass",
        )
        if not here:
            report.warn(
                "start the transfer from the spare account and set TRANSFER_PASSWORD. "
                "AWS cancels an unaccepted account-to-account transfer after three days"
            )
    else:
        report.check(
            here,
            f"{profile.domain} is already held here, as 'bypass' expects",
            f"{profile.domain} is NOT in this account; bypass would seal an account "
            "without a domain and the bring-up would fail at the registrar",
        )


def dispatch_command(profile, start):
    return " ".join([
        "gh workflow run", profile.caller_workflow,
        "--repo", profile.caller,
        "-f", f"domain={profile.domain}",
        "-f", f"start={start}",
        "-f", f"repo={profile.app.repo}",
        "-f", "bypass_event_check=true",
        "-f", f"bypass_domain_transfer={str(profile.bypass_domain_transfer).lower()}",
    ])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default=os.environ.get("ENCLAVIZE_E2E_PROFILE"))
    parser.add_argument("--region", default=os.environ.get("ENCLAVIZE_TEST_REGION", "us-east-1"))
    args = parser.parse_args(argv)

    if not args.profile:
        raise SystemExit("ENCLAVIZE_E2E_PROFILE (or --profile) is required")
    profile = load_profile(args.profile)

    report = Report()
    print(f"\nprofile   {args.profile}")
    print(f"caller    {profile.caller} ({profile.caller_workflow})")
    print(f"domain    {profile.domain}")
    print(f"app       {profile.app.repo}")
    print(f"transfer  {profile.transfer}\n")

    secrets = gh("secret", "list", "--repo", profile.caller,
                 "--json", "name,updatedAt", parse_json=True) or []
    account, arn = check_identity(report, args.region)
    if account:
        session = boto3.Session(region_name=args.region)
        check_root_keys(report, session, profile, arn)
        check_account_is_clean(report, session, profile, account)
        check_domain(report, session, profile)
    check_caller(report, profile, secrets)
    check_the_root_key_secret_is_not_spent(report, profile, secrets)

    report.check(
        bool(os.environ.get("ENCLAVIZE_APPLY_API_KEY")),
        "ENCLAVIZE_APPLY_API_KEY is set",
        "ENCLAVIZE_APPLY_API_KEY is not set — stage 3 calls the apply endpoint",
    )
    if not os.environ.get("ENCLAVIZE_CONSOLE_ZIP_PASSWORD"):
        report.warn("ENCLAVIZE_CONSOLE_ZIP_PASSWORD is not set; the console archive check will skip")

    print()
    if report.failures:
        print(f"{report.failures} problem(s) to fix before dispatching.\n")
        return 1

    start = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 600
    print("ready. This is the run stage 1 would dispatch:\n")
    print(f"  {dispatch_command(profile, start)}\n")
    if report.warnings:
        print(f"({report.warnings} warning(s) above.)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
