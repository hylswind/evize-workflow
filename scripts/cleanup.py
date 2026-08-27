"""Take an enclavized account apart with nothing but credentials.

    python scripts/cleanup.py

For a run that went wrong: a seal whose audit refused it, a bring-up that died
halfway, an account in a state no profile describes. After an ordinary
end-to-end cycle use `tests/e2e/unseal.py` instead — it also runs the
application's own teardown, which needs the profile that names it.

Three differences, and each is why this exists rather than a flag on the other:

- **No profile.** The domain is read from the account itself: the hosted zone
  enclavize stamped as its own, or failing that the domain the registrar says
  this account holds.
- **No environment.** Instead of an allow-list it prints the account and the
  domain and makes you type the account id back. A gate you have to read beats
  one exported once and forgotten.
- **The application's own resources are neither removed nor noticed.** The
  survey at the end looks only for what enclavize built — by prefix, creation
  stamp, or a name derived from the domain — so it will report a clean account
  while whatever an application created is still standing. Removing that is
  separate work: enclavize asks an application for a setup.sh and nothing else,
  so there may be no teardown to run at all.

Every delete step is scripts/dismantle.py's, shared with unseal.py so the two
cannot drift.
"""

import argparse
import pathlib
import sys

import boto3

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import dismantle  # noqa: E402
from enclavize.aws import domains as domainsmod  # noqa: E402
from enclavize.logic import naming  # noqa: E402


def discover_domain(session):
    """Which domain this account was enclavized for, according to the account.

    The hosted zone first, because its creation stamp says enclavize made it. A
    registered domain proves only that the account holds one, which is also true
    of an account no run ever touched.
    """
    r53 = session.client("route53")
    for zone in r53.list_hosted_zones()["HostedZones"]:
        if naming.is_ours(zone.get("CallerReference")):
            return zone["Name"].rstrip("."), f"hosted zone {zone['Id'].split('/')[-1]}"

    domains = session.client("route53domains", region_name=domainsmod.REGION)
    held = [d["DomainName"] for page in domains.get_paginator("list_domains").paginate()
            for d in page["Domains"]]
    if len(held) == 1:
        return held[0], "the only domain this account holds"
    if held:
        raise SystemExit(
            f"this account holds {len(held)} domains and no hosted zone enclavize created, "
            f"so which one a run was for cannot be told: {', '.join(held)}.\n"
            "Pass --domain to say which."
        )
    raise SystemExit(
        "no hosted zone enclavize created, and no domain registered here — nothing says "
        "what this account was enclavized for. Pass --domain to say."
    )


def unfit(arn: str) -> str:
    """Why these credentials could not finish the job, if so.

    A principal carrying the apply boundary is denied iam:* on the enclave
    identities and signin:* outright, so it would strip half the account and
    leave the console locked for good.
    """
    if arn.endswith(":root"):
        return ""
    user = boto3.client("iam").get_user()["User"]
    if user.get("PermissionsBoundary"):
        return (
            f"{arn} carries a permissions boundary "
            f"({user['PermissionsBoundary'].get('PermissionsBoundaryArn')}). It cannot "
            "remove the enclave identities or unlock the console, so it would leave the "
            "account worse than it found it."
        )
    return ""


def confirm(account, domain, source):
    print(f"\naccount  {account}")
    print(f"domain   {domain}   (from {source})")
    print("\nThis removes everything enclavize built: both distributions, the two")
    print("buckets, the hosted zone and its records, the enclavize-* identities, the")
    print("sign-in lock, the apply machinery, the anchor VPC and the certificate.")
    print("\nAn application's own resources are NOT removed, and NOT reported either —")
    print("nothing here knows what one built. Removing them is yours to do.")
    if input("\nType the account id to confirm: ").strip() != account:
        raise SystemExit("that is not the account id; nothing was touched.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--domain", help="skip discovery and use this domain")
    parser.add_argument("--yes", action="store_true", help="do not ask")
    args = parser.parse_args(argv)

    session = boto3.Session(region_name=args.region)
    identity = session.client("sts").get_caller_identity()
    account, arn = identity["Account"], identity["Arn"]

    problem = unfit(arn)
    if problem:
        raise SystemExit(f"refusing to run: {problem}")

    domain, source = (args.domain, "--domain") if args.domain else discover_domain(session)
    if not args.yes:
        confirm(account, domain, source)

    dismantle.everything(session, account, domain)
    dismantle.report(session, account, domain)

    print("\nThe sign-in lock is gone; the console signs in normally again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
