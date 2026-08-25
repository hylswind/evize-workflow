"""Delete what a real-account test left behind.

Every real-account test cleans up after itself, but a test that dies partway
cannot. This finds whatever is left carrying a run's prefix and removes it.

    python tests/aws/reaper.py --prefix t1a2b3c4- [--region us-east-1] [--yes]

Every deletion is announced before it happens, and nothing runs against an
account outside ENCLAVIZE_TEST_ACCOUNTS.
"""

import argparse
import os
import pathlib
import sys

import boto3
from botocore.exceptions import ClientError

# Run directly as a script, so the repo root has to be found rather than assumed.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from enclavize.aws import iam as iammod, s3 as s3mod  # noqa: E402


def check_account(session) -> str:
    # The allow-list is checked before any call is made, so a run against an
    # unconfigured machine never reaches AWS at all.
    allowed = {a.strip() for a in os.environ.get("ENCLAVIZE_TEST_ACCOUNTS", "").split(",") if a.strip()}
    if not allowed:
        raise SystemExit("ENCLAVIZE_TEST_ACCOUNTS must list the accounts the reaper may touch")
    account = session.client("sts").get_caller_identity()["Account"]
    if account not in allowed:
        raise SystemExit(f"refusing to run: {account} is not in ENCLAVIZE_TEST_ACCOUNTS")
    return account


def find(session, prefix: str) -> list:
    """Everything carrying the prefix, as (kind, name, delete) triples."""
    iam = session.client("iam")
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    found = []

    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            if user["UserName"].startswith(prefix):
                found.append(("user", user["UserName"],
                              lambda n=user["UserName"]: iammod.delete_user(iam, user=n)))

    for page in iam.get_paginator("list_instance_profiles").paginate():
        for profile in page["InstanceProfiles"]:
            if profile["InstanceProfileName"].startswith(prefix):
                found.append(("instance-profile", profile["InstanceProfileName"],
                              lambda n=profile["InstanceProfileName"]: iammod.delete_instance_profile(iam, name=n)))

    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            if role["RoleName"].startswith(prefix):
                found.append(("role", role["RoleName"],
                              lambda n=role["RoleName"]: iammod.delete_role(iam, role=n)))

    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for policy in page["Policies"]:
            if policy["PolicyName"].startswith(prefix):
                found.append(("policy", policy["PolicyName"],
                              lambda a=policy["Arn"]: iammod.delete_policy(iam, policy_arn=a)))

    for bucket in s3.list_buckets()["Buckets"]:
        if bucket["Name"].startswith(prefix):
            found.append(("bucket", bucket["Name"],
                          lambda n=bucket["Name"]: s3mod.delete_bucket(s3, n)))

    for reservation in ec2.describe_instances(
        Filters=[{"Name": "tag:Name", "Values": [f"{prefix}*"]},
                 {"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]}]
    )["Reservations"]:
        for instance in reservation["Instances"]:
            found.append(("instance", instance["InstanceId"],
                          lambda i=instance["InstanceId"]: ec2.terminate_instances(InstanceIds=[i])))

    for vpc in ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [f"{prefix}*"]}])["Vpcs"]:
        found.append(("vpc", vpc["VpcId"], lambda v=vpc["VpcId"]: ec2.delete_vpc(VpcId=v)))

    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, help="the per-run prefix to delete")
    parser.add_argument("--region", default=os.environ.get("ENCLAVIZE_TEST_REGION", "us-east-1"))
    parser.add_argument("--yes", action="store_true", help="delete without asking")
    args = parser.parse_args(argv)

    if len(args.prefix) < 4:
        raise SystemExit("refusing to reap on a prefix that short")

    session = boto3.Session(region_name=args.region)
    account = check_account(session)

    found = find(session, args.prefix)
    if not found:
        print(f"nothing left with prefix {args.prefix} in {account}")
        return 0

    print(f"in account {account}:")
    for kind, name, _ in found:
        print(f"  {kind:16} {name}")
    if not args.yes and input(f"delete these {len(found)}? [y/N] ").strip().lower() != "y":
        return 1

    for kind, name, delete in found:
        try:
            delete()
            print(f"  deleted {kind} {name}")
        except ClientError as exc:
            print(f"  could not delete {kind} {name}: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
