"""Undo a run, so the account can be used for the next one.

    ENCLAVIZE_E2E_PROFILE=tests/e2e/profiles/mine.yml \
    ENCLAVIZE_TEST_ACCOUNTS=111122223333 \
      python tests/e2e/unseal.py [--yes] [--send-domain-back <account-id>]

This is what makes the cycle repeatable, and it is the slow part: disabling a
CloudFront distribution and waiting for the change to reach the edge takes
roughly twenty minutes, and nothing else can be deleted until it has. Every step
tolerates its target already being gone, so a run that dies partway can simply
be run again.

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
from botocore.exceptions import ClientError

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from enclavize.aws import acm as acmmod  # noqa: E402
from enclavize.aws import apigw as apigwmod  # noqa: E402
from enclavize.aws import cdn as cdnmod  # noqa: E402
from enclavize.aws import dns as dnsmod  # noqa: E402
from enclavize.aws import ec2 as ec2mod  # noqa: E402
from enclavize.aws import iam as iammod  # noqa: E402
from enclavize.aws import s3 as s3mod  # noqa: E402
from enclavize.aws import sfn as sfnmod  # noqa: E402
from enclavize.aws import signin as signinmod  # noqa: E402
from enclavize.aws import ssm as ssmmod  # noqa: E402
from enclavize.logic import naming  # noqa: E402
from conftest import unfit_to_unseal  # noqa: E402
from harness import load_profile  # noqa: E402
from setup import config as setup_config  # noqa: E402
from workflow import config as workflow_config  # noqa: E402

RESOURCES = workflow_config.RESOURCES
SETUP_RESOURCES = setup_config.RESOURCES

DISTRIBUTION_POLL_MAX = 2400
DISTRIBUTION_POLL_INTERVAL = 30


def step(message):
    print(f"\n== {message}")


def attempt(what, action):
    """Run one deletion, reporting rather than raising. Everything here is
    'remove it if it is there', and a half-finished teardown must be re-runnable.
    """
    try:
        action()
        print(f"   deleted {what}")
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchEntity", "NoSuchBucket", "NotFoundException", "NoSuchDistribution",
                    "ResourceNotFoundException", "InvalidParameterValue", "ParameterNotFound",
                    "NoSuchHostedZone", "ValidationError"):
            print(f"   (already gone) {what}")
        else:
            print(f"   COULD NOT delete {what}: {exc}")
        return False
    except Exception as exc:  # noqa: BLE001
        print(f"   COULD NOT delete {what}: {exc}")
        return False


def check_account(session):
    allowed = {a.strip() for a in os.environ.get("ENCLAVIZE_TEST_ACCOUNTS", "").split(",") if a.strip()}
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
    teardown that cannot be written generically here. Run first, because an
    application usually has DNS records to tidy and the hosted zone is deleted
    below.

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

        result = subprocess.run(
            ["bash", str(script)], cwd=workdir,
            env={**os.environ,
                 "AWS_DEFAULT_REGION": region,
                 "ENCLAVIZE_REGION": region,
                 "ENCLAVIZE_DOMAIN": profile.domain},
        )
        print(f"   {profile.app.teardown} exited {result.returncode}")
    except subprocess.CalledProcessError as exc:
        print(f"   COULD NOT fetch {profile.app.repo}: {exc.stderr or exc}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --- enclavize's own ------------------------------------------------------


def terminate_instances(session):
    ec2 = session.client("ec2")
    live = [
        instance["InstanceId"]
        for reservation in ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]}]
        )["Reservations"]
        for instance in reservation["Instances"]
    ]
    if not live:
        print("   (none running)")
        return
    attempt(f"{len(live)} instance(s)", lambda: ec2.terminate_instances(InstanceIds=live))


def delete_apply_api(session, profile):
    apigw = session.client("apigateway")
    host = naming.apply_host(profile.domain)

    for mapping in _safe(lambda: apigw.get_base_path_mappings(domainName=host)["items"], []):
        attempt(f"base path mapping /{mapping['basePath']}",
                lambda m=mapping: apigw.delete_base_path_mapping(
                    domainName=host, basePath=m["basePath"]))
    attempt(f"custom domain {host}", lambda: apigwmod.delete_custom_domain(apigw, host))

    for plan in _safe(lambda: apigw.get_usage_plans()["items"], []):
        if plan["name"].startswith(SETUP_RESOURCES.prefix):
            for key in _safe(lambda p=plan: apigw.get_usage_plan_keys(usagePlanId=p["id"])["items"], []):
                attempt(f"usage plan key {key['id']}",
                        lambda p=plan, k=key: apigwmod.delete_usage_plan(
                            apigw, plan_id=p["id"], key_id=k["id"]))
            attempt(f"usage plan {plan['name']}",
                    lambda p=plan: apigwmod.delete_usage_plan(apigw, plan_id=p["id"]))

    for key in _safe(lambda: apigw.get_api_keys()["items"], []):
        if key["name"].startswith(SETUP_RESOURCES.prefix):
            attempt(f"api key {key['name']}", lambda k=key: apigwmod.delete_api_key(apigw, k["id"]))

    for api in _safe(lambda: apigw.get_rest_apis()["items"], []):
        if api["name"].startswith(SETUP_RESOURCES.prefix):
            attempt(f"rest api {api['name']}", lambda a=api: apigwmod.delete_api(apigw, a["id"]))


def delete_state_machines(session):
    sfn = session.client("stepfunctions")
    for machine in _safe(lambda: sfn.list_state_machines()["stateMachines"], []):
        if machine["name"].startswith(SETUP_RESOURCES.prefix):
            attempt(f"state machine {machine['name']}",
                    lambda m=machine: sfnmod.delete_state_machine(sfn, m["stateMachineArn"]))


def delete_distributions(session):
    """Both together. Disabling one takes about twenty minutes to reach the
    edge, and doing them in turn would cost that twice."""
    cf = session.client("cloudfront")
    items = [
        item
        for page in cf.get_paginator("list_distributions").paginate()
        for item in page.get("DistributionList", {}).get("Items", [])
    ]
    if not items:
        print("   (none)")
        return

    for item in items:
        if item["Enabled"]:
            attempt(f"disable {item['Id']}", lambda i=item: cdnmod.disable(cf, i["Id"]))
        else:
            print(f"   {item['Id']} already disabled")

    print(f"   waiting for {len(items)} distribution(s) to redeploy — this is the slow part")
    for item in items:
        if not cdnmod.await_deployed(cf, item["Id"], poll_max=DISTRIBUTION_POLL_MAX,
                                     interval=DISTRIBUTION_POLL_INTERVAL):
            print(f"   {item['Id']} has not finished; re-run unseal.py to pick up from here")
    for item in items:
        attempt(f"distribution {item['Id']}", lambda i=item: cdnmod.delete(cf, i["Id"]))


def delete_certificates(session, profile):
    """After the distributions: ACM refuses to delete one still in use."""
    acm = session.client("acm")
    wanted = {naming.dashboard_host(profile.domain), naming.proof_host(profile.domain),
              naming.apply_host(profile.domain)}
    for page in acm.get_paginator("list_certificates").paginate():
        for certificate in page["CertificateSummaryList"]:
            if certificate["DomainName"] in wanted:
                attempt(f"certificate for {certificate['DomainName']}",
                        lambda c=certificate: acmmod.delete_certificate(acm, c["CertificateArn"]))


def delete_buckets(session, account):
    s3 = session.client("s3")
    for bucket in (naming.proof_bucket_name(account), naming.dashboard_bucket_name(account)):
        attempt(f"bucket {bucket}", lambda b=bucket: s3mod.delete_bucket(s3, b))


def delete_zone(session, profile):
    r53 = session.client("route53")
    zones = [z for z in _safe(
        lambda: r53.list_hosted_zones_by_name(DNSName=profile.domain)["HostedZones"], [])
        if z["Name"].rstrip(".") == profile.domain]
    if not zones:
        print("   (no hosted zone)")
        return
    zone_id = zones[0]["Id"].split("/")[-1]

    # NS and SOA at the apex cannot be deleted and are removed with the zone.
    doomed = [
        record
        for page in r53.get_paginator("list_resource_record_sets").paginate(HostedZoneId=zone_id)
        for record in page["ResourceRecordSets"]
        if not (record["Name"].rstrip(".") == profile.domain and record["Type"] in ("NS", "SOA"))
    ]
    if doomed:
        attempt(
            f"{len(doomed)} record(s) in {profile.domain}",
            lambda: dnsmod.change_records(
                r53, zone_id=zone_id,
                changes=[{"Action": "DELETE", "ResourceRecordSet": r} for r in doomed],
                comment="enclavize teardown",
            ),
        )
    attempt(f"hosted zone {zone_id}", lambda: dnsmod.delete_zone(r53, zone_id))


def delete_identities(session, account):
    iam = session.client("iam")
    attempt(f"instance profile {RESOURCES.instance_profile()}",
            lambda: iammod.delete_instance_profile(iam, name=RESOURCES.instance_profile()))
    for role in (RESOURCES.admin_role, SETUP_RESOURCES.apply_role,
                 SETUP_RESOURCES.apply_sfn_role, SETUP_RESOURCES.apply_api_role):
        attempt(f"role {role}", lambda r=role: iammod.delete_role(iam, role=r))
    for user in (RESOURCES.event_reader_user, RESOURCES.starter_user, RESOURCES.console_user):
        attempt(f"user {user}", lambda u=user: iammod.delete_user(iam, user=u))
    attempt(f"policy {SETUP_RESOURCES.apply_boundary}",
            lambda: iammod.delete_policy(iam, policy_arn=SETUP_RESOURCES.apply_boundary_arn(account)))


def unlock_console(session, account):
    signin = session.client("signin", region_name="us-east-1")
    statements = _safe(lambda: signinmod.list_statements(signin), [])
    if not statements:
        print("   (no sign-in statements)")
    for statement in statements:
        sid = statement.get("statementId") or statement.get("StatementId")
        attempt(f"sign-in statement {sid}",
                lambda s=sid: signinmod.disable_lock(signin, account_id=account, statement_id=s))


def delete_anchor_vpcs(session):
    ec2 = session.client("ec2")
    for vpc in _safe(lambda: ec2.describe_vpcs(
            Filters=[{"Name": "tag:Name", "Values": [RESOURCES.signin_lock_vpc_tag]}])["Vpcs"], []):
        attempt(f"anchor vpc {vpc['VpcId']}", lambda v=vpc: ec2mod.delete_vpc(ec2, v["VpcId"]))


def send_domain_back(session, profile, target):
    """The half of a transfer this account can perform. The other half —
    accepting it — has to happen on the spare account."""
    response = session.client("route53domains", region_name="us-east-1") \
        .transfer_domain_to_another_aws_account(DomainName=profile.domain, AccountId=target)
    print(f"\n== {profile.domain} offered to {target}")
    print(f"   password: {response['Password']}")
    print("   Accept it from that account within three days, or AWS cancels the transfer:")
    print("     aws route53domains accept-domain-transfer-from-another-aws-account \\")
    print(f"       --domain-name {profile.domain} --password '{response['Password']}' --region us-east-1")


def survey(session, account):
    """What is still standing. An application's teardown missing something shows
    up here rather than in the next cycle's preflight."""
    ec2 = session.client("ec2")
    leftovers = []
    for reservation in _safe(lambda: ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]}]
    )["Reservations"], []):
        leftovers += [f"instance {i['InstanceId']}" for i in reservation["Instances"]]
    for balancer in _safe(
        lambda: session.client("elbv2").describe_load_balancers()["LoadBalancers"], []
    ):
        leftovers.append(f"load balancer {balancer['LoadBalancerName']}")
    for bucket in _safe(lambda: session.client("s3").list_buckets()["Buckets"], []):
        leftovers.append(f"bucket {bucket['Name']}")
    for group in _safe(lambda: ec2.describe_security_groups()["SecurityGroups"], []):
        if group["GroupName"] != "default":
            leftovers.append(f"security group {group['GroupName']}")
    return leftovers


def _safe(call, default):
    try:
        return call()
    except Exception:  # noqa: BLE001 - surveying must never be the thing that fails
        return default


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

    step("the application's own resources")
    run_app_teardown(profile, region=args.region, assume_yes=args.yes)

    step("instances")
    terminate_instances(session)

    step("the apply API")
    delete_apply_api(session, profile)

    step("the state machine")
    delete_state_machines(session)

    step("the distributions")
    delete_distributions(session)

    step("the certificate")
    delete_certificates(session, profile)

    step("the buckets")
    delete_buckets(session, account)

    step("the hosted zone")
    delete_zone(session, profile)

    step("the identities")
    delete_identities(session, account)

    step("the console lock")
    unlock_console(session, account)

    step("the anchor VPC")
    delete_anchor_vpcs(session)

    step("the go flag")
    attempt(RESOURCES.go_param,
            lambda: ssmmod.delete_parameter(session.client("ssm"), RESOURCES.go_param))

    if args.send_domain_back:
        send_domain_back(session, profile, args.send_domain_back)

    leftovers = survey(session, account)
    print("\n== still standing")
    if leftovers:
        for item in leftovers:
            print(f"   {item}")
        print("\n   Remove these before the next cycle; preflight will refuse until it is clean.")
    else:
        print("   nothing. The account is ready for another run.")

    print(f"\nThe console is open again for {RESOURCES.console_user}; your own credentials are untouched.")
    print("This account can never pass the event audit again — which is the audit working,")
    print("not a flaw: a way back in is exactly what enclavize is meant to leave nobody.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
