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
from botocore.exceptions import ClientError

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from enclavize.aws import signin as signinmod  # noqa: E402
from enclavize.logic import naming  # noqa: E402
from harness import (  # noqa: E402
    ProfileError,
    caller_problems,
    caller_workflow_text,
    derive_caller,
    gh,
    load_profile,
)
from setup import config as setup_config  # noqa: E402
from workflow import config as workflow_config  # noqa: E402

OK, BAD, WARN = "  ok  ", " FAIL ", " warn "


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
    """Root of an allow-listed account, or nothing else can be trusted."""
    allowed = {a.strip() for a in os.environ.get("ENCLAVIZE_TEST_ACCOUNTS", "").split(",") if a.strip()}
    if not allowed:
        report.bad("ENCLAVIZE_TEST_ACCOUNTS is empty; refusing to look at any account")
        return None

    identity = boto3.client("sts", region_name=region).get_caller_identity()
    account, arn = identity["Account"], identity["Arn"]

    if not report.check(
        account in allowed,
        f"account {account} is allow-listed",
        f"account {account} is NOT in ENCLAVIZE_TEST_ACCOUNTS",
    ):
        return None
    report.check(
        arn.endswith(":root"),
        "credentials are the root user, so the account can be unsealed afterwards",
        f"{arn} is not root; without the rescue root key this account is spent after one run",
    )
    return account


def check_root_keys(report, session, profile):
    """AWS allows two access keys per user, root included — and the loop needs
    both: one for the workflow to delete, one to get back in with. So the
    interesting failure is a leftover from last time, which leaves no room."""
    iam = session.client("iam")
    keys = iam.list_access_keys()["AccessKeyMetadata"]

    if not keys:
        report.bad("root has no access key; the workflow needs one and you need a rescue key")
        return
    for key in keys:
        role = "rescue" if key["AccessKeyId"] == profile.rescue_key_id else "for the workflow"
        print(f"          {key['AccessKeyId']}  {key['CreateDate']:%Y-%m-%d %H:%M}  ({role})")

    if profile.rescue_key_id and profile.rescue_key_id not in {k["AccessKeyId"] for k in keys}:
        report.bad(f"the profile's rescueKeyId {profile.rescue_key_id} does not exist on this account")
        return

    if len(keys) == 1:
        report.warn("only one root key: mint the second and set ROOT_KEY_ID before dispatching")
    elif len(keys) == 2:
        report.ok("two root keys, which is the AWS maximum — one to spend, one to keep")
    else:
        report.bad(f"{len(keys)} root keys; expected at most two")


def check_account_is_clean(report, session, profile, account):
    """That the last teardown finished. A leftover is not merely untidy: a
    surviving role or bucket makes the next run fail deep inside the bring-up."""
    res, setup_res = workflow_config.RESOURCES, setup_config.RESOURCES
    iam, s3 = session.client("iam"), session.client("s3")
    leftovers = []

    for role in (res.admin_role, setup_res.apply_role, setup_res.apply_sfn_role, setup_res.apply_api_role):
        try:
            iam.get_role(RoleName=role)
            leftovers.append(f"role {role}")
        except ClientError:
            pass

    for user in (res.event_reader_user, res.starter_user, res.console_user):
        try:
            iam.get_user(UserName=user)
            leftovers.append(f"user {user}")
        except ClientError:
            pass

    try:
        iam.get_policy(PolicyArn=setup_res.apply_boundary_arn(account))
        leftovers.append(f"policy {setup_res.apply_boundary}")
    except ClientError:
        pass

    for bucket in (naming.proof_bucket_name(account), naming.dashboard_bucket_name(account)):
        try:
            s3.head_bucket(Bucket=bucket)
            leftovers.append(f"bucket {bucket}")
        except ClientError:
            pass

    statements = signinmod.list_statements(session.client("signin", region_name="us-east-1"))
    if statements:
        leftovers.append(f"{len(statements)} sign-in permission statement(s) — the console is still locked")

    zones = session.client("route53").list_hosted_zones_by_name(DNSName=profile.domain)["HostedZones"]
    if any(z["Name"].rstrip(".") == profile.domain for z in zones):
        leftovers.append(f"hosted zone for {profile.domain}")

    ec2 = session.client("ec2")
    running = [
        instance["InstanceId"]
        for reservation in ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]}]
        )["Reservations"]
        for instance in reservation["Instances"]
    ]
    if running:
        leftovers.append(f"{len(running)} live instance(s): {', '.join(running)}")

    try:
        session.client("ssm").get_parameter(Name=res.go_param)
        leftovers.append(f"go flag {res.go_param} is still set")
    except ClientError:
        pass

    if leftovers:
        report.bad("the previous teardown did not finish — run unseal.py first:")
        for item in leftovers:
            print(f"          - {item}")
    else:
        report.ok("account is clean; nothing left from a previous run")


def check_caller(report, profile):
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

    have = {s["name"] for s in gh("secret", "list", "--repo", profile.caller,
                                 "--json", "name", parse_json=True) or []}
    missing = caller.secrets - have
    if missing:
        report.bad(f"{profile.caller} is missing secrets: {', '.join(sorted(missing))}")
    else:
        report.ok(f"all {len(caller.secrets)} secrets the caller passes down are set")
    return caller


def check_domain(report, session, profile):
    """Membership, not an error code: `real` needs the domain elsewhere and
    `bypass` needs it here, and getting this wrong wastes a whole cycle."""
    domains = session.client("route53domains", region_name="us-east-1")
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

    account = check_identity(report, args.region)
    if account:
        session = boto3.Session(region_name=args.region)
        check_root_keys(report, session, profile)
        check_account_is_clean(report, session, profile, account)
        check_domain(report, session, profile)
    check_caller(report, profile)

    for name, why in (("ENCLAVIZE_APPLY_API_KEY", "stage 3 calls the apply endpoint"),):
        report.check(bool(os.environ.get(name)), f"{name} is set", f"{name} is not set — {why}")
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
