"""Undo an end-to-end cycle, so the account can be used for the next one.

    ENCLAVIZE_E2E_PROFILE=tests/e2e/profiles/mine.yml \
    ENCLAVIZE_TEST_ACCOUNTS=111122223333 \
      python tests/e2e/unseal.py [--yes] [--send-domain-back <account-id>]

What this adds over `scripts/cleanup.py` is the profile: the application's own
teardown script, and an allow-list of accounts this may be pointed at. Every
delete step itself is scripts/dismantle.py's, shared so the two cannot drift.

It is the slow part of a cycle: disabling a CloudFront distribution and waiting
for the change to reach the edge takes roughly twenty minutes, and nothing else
can be deleted until it has.

Needs credentials that outlive the seal and are not capped by the apply
boundary: root, or an admin IAM user created before the run. Sign-in policies
never apply to signed API calls, so the locked console is no obstacle.

⚠️ Doing this permanently disqualifies the account from ever passing the audit.
Whichever identity is used, its trail is the pattern the audit looks for: root
calls carrying no request id enclavize recorded, or — for an IAM user — the
`iam:CreateUser` that minted it, which is on no allow-list.
"""

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import boto3

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))

import dismantle  # noqa: E402
from harness import allowed_accounts, load_profile, unfit_to_unseal  # noqa: E402


def check_account(session):
    allowed = allowed_accounts()
    if not allowed:
        raise SystemExit("ENCLAVIZE_TEST_ACCOUNTS must list the accounts this may dismantle")
    identity = session.client("sts").get_caller_identity()
    if identity["Account"] not in allowed:
        raise SystemExit(f"refusing to run: {identity['Account']} is not in ENCLAVIZE_TEST_ACCOUNTS")
    problem = unfit_to_unseal(identity["Arn"], session.region_name)
    if problem:
        raise SystemExit(f"refusing to run: {problem}")
    return identity["Account"]


# --- the application's own resources --------------------------------------


def run_app_teardown(profile, *, region, assume_yes):
    """Let the application remove what it created, before the zone goes.

    Only the application knows what it built, so this is the one part of the
    teardown that cannot be written generically here. It runs early, because an
    application usually has DNS records to tidy and the hosted zone is deleted
    below — but after the instances, which it does not own and cannot remove.

    ⚠️ This executes a script from another repository on this machine, with
    credentials that bypass the permission boundary — a wider grant than the
    same script gets inside the account. Hence showing it first.
    """
    if not profile.app.teardown:
        print("   no app.teardown in the profile — the application's own resources are")
        print("   NOT being removed. They are listed at the end.")
        return

    workdir = tempfile.mkdtemp(prefix="enclavize-app-")
    try:
        subprocess.run(
            ["git", "clone", "--quiet", f"https://github.com/{profile.app.repo}.git", workdir],
            check=True, capture_output=True,
        )
        if profile.app.ref:
            subprocess.run(["git", "-C", workdir, "checkout", "--quiet", profile.app.ref],
                           check=True, capture_output=True)
        sha = subprocess.run(["git", "-C", workdir, "rev-parse", "HEAD"],
                             check=True, capture_output=True, text=True).stdout.strip()

        script = pathlib.Path(workdir) / profile.app.teardown
        if not script.exists():
            print(f"   {profile.app.repo}@{sha[:12]} has no {profile.app.teardown}; skipping")
            return

        print(f"   {profile.app.repo}@{sha} :: {profile.app.teardown}")
        print("   " + "-" * 68)
        for line in script.read_text(encoding="utf-8", errors="replace").splitlines():
            print(f"   | {line}")
        print("   " + "-" * 68)
        print("   This runs here, with credentials that bypass the permission boundary.")
        if not assume_yes and input("   run it? [y/N] ").strip().lower() != "y":
            print("   skipped.")
            return

        # The same thing an apply instance hands setup.sh, and nothing more:
        # a teardown written against a wider environment than its setup.sh gets
        # would work here and fail where it matters.
        result = subprocess.run(
            ["bash", str(script)], cwd=workdir,
            env={**os.environ, "ENCLAVIZE_DOMAIN": profile.domain},
        )
        print(f"   {profile.app.teardown} exited {result.returncode}")
    except subprocess.CalledProcessError as exc:
        print(f"   COULD NOT fetch {profile.app.repo}: {exc.stderr or exc}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default=os.environ.get("ENCLAVIZE_E2E_PROFILE"))
    parser.add_argument("--region", default=os.environ.get("ENCLAVIZE_TEST_REGION", "us-east-1"))
    parser.add_argument("--yes", action="store_true", help="do not ask before anything")
    parser.add_argument("--send-domain-back", metavar="ACCOUNT_ID",
                        help="offer the domain back to the spare account afterwards")
    args = parser.parse_args(argv)

    if not args.profile:
        raise SystemExit("ENCLAVIZE_E2E_PROFILE (or --profile) is required")
    profile = load_profile(args.profile)

    session = boto3.Session(region_name=args.region)
    account = check_account(session)

    print(f"\nAbout to dismantle everything enclavize built in account {account}")
    print(f"domain {profile.domain}, application {profile.app.repo}")
    print("This takes roughly 25 minutes, most of it waiting on CloudFront.")
    if not args.yes and input("continue? [y/N] ").strip().lower() != "y":
        return 1

    dismantle.everything(
        session, account, profile.domain,
        after_instances=lambda: run_app_teardown(
            profile, region=args.region, assume_yes=args.yes),
    )

    if args.send_domain_back:
        dismantle.send_domain_back(session, profile.domain, args.send_domain_back)

    dismantle.report(session, account, profile.domain)

    print("\nThe sign-in lock is gone; the console signs in normally again.")
    print("This account can never pass the event audit again — which is the audit working,")
    print("not a flaw: a way back in is exactly what enclavize is meant to leave nobody.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
