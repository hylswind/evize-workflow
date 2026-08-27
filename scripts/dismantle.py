"""Take apart everything enclavize built in an account.

Every delete step, and the order the dependencies between them allow. Two
entry points share it — `scripts/cleanup.py` and `tests/e2e/unseal.py` — because
the order is not arbitrary and a second copy of it would drift.

Nothing here belongs to the three-layer rule that governs the rest of the
project: a teardown reaches for whatever boto3 call removes a thing, and
`tests/aws/reaper.py` set that precedent.

Every step tolerates its target already being gone, so a run that dies partway
can simply be run again.
"""

import pathlib
import sys
import time

from botocore.exceptions import ClientError

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from enclavize.aws import acm as acmmod  # noqa: E402
from enclavize.aws import apigw as apigwmod  # noqa: E402
from enclavize.aws import cdn as cdnmod  # noqa: E402
from enclavize.aws import dns as dnsmod  # noqa: E402
from enclavize.aws import domains as domainsmod  # noqa: E402
from enclavize.aws import ec2 as ec2mod  # noqa: E402
from enclavize.aws import iam as iammod  # noqa: E402
from enclavize.aws import s3 as s3mod  # noqa: E402
from enclavize.aws import sfn as sfnmod  # noqa: E402
from enclavize.aws import signin as signinmod  # noqa: E402
from enclavize.aws import ssm as ssmmod  # noqa: E402
from enclavize.logic import naming  # noqa: E402
from setup import config as setup_config  # noqa: E402
from workflow import config as workflow_config  # noqa: E402

RESOURCES = workflow_config.RESOURCES
SETUP_RESOURCES = setup_config.RESOURCES

DISTRIBUTION_POLL_MAX = 2400
DISTRIBUTION_POLL_INTERVAL = 30

# A distribution hands its certificate back well after it is itself gone.
CERTIFICATE_RELEASE_ATTEMPTS = 20
CERTIFICATE_RELEASE_INTERVAL = 30


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
        # Absence only. A malformed request is not the same as a thing that has
        # already gone, and reporting it as one would have the survey below call
        # the account clean.
        if code in ("NoSuchEntity", "NoSuchBucket", "NotFoundException", "NoSuchDistribution",
                    "ResourceNotFoundException", "ParameterNotFound", "NoSuchHostedZone"):
            print(f"   (already gone) {what}")
        else:
            print(f"   COULD NOT delete {what}: {exc}")
        return False
    except Exception as exc:  # noqa: BLE001
        print(f"   COULD NOT delete {what}: {exc}")
        return False


def _safe(call, default):
    try:
        return call()
    except Exception:  # noqa: BLE001 - surveying must never be the thing that fails
        return default


# --- enclavize's own ------------------------------------------------------


def terminate_instances(session):
    """Only the ones enclavize launched, by the name it tagged them with.

    An account may be running things of its own, and an application's instances
    are its teardown's business — they are reported at the end if it misses any.
    """
    ec2 = session.client("ec2")
    live = [
        instance["InstanceId"]
        for reservation in ec2.describe_instances(
            Filters=[
                {"Name": "tag:Name", "Values": [f"{RESOURCES.prefix}*"]},
                {"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]},
            ]
        )["Reservations"]
        for instance in reservation["Instances"]
    ]
    if not live:
        print("   (none of the enclave's own running)")
        return
    if not attempt(f"{len(live)} instance(s)", lambda: ec2.terminate_instances(InstanceIds=live)):
        return
    # Waited out rather than fired and forgotten: an instance keeps hold of its
    # security groups until it has actually gone, and the application's teardown
    # runs next expecting to delete the ones it attached.
    print("   waiting for them to go, so the groups they hold are released")
    _safe(lambda: ec2.get_waiter("instance_terminated").wait(InstanceIds=live), None)


def delete_apply_api(session, domain):
    apigw = session.client("apigateway")
    host = naming.apply_host(domain)

    for mapping in _safe(lambda: apigw.get_base_path_mappings(domainName=host)["items"], []):
        attempt(f"base path mapping /{mapping['basePath']}",
                lambda m=mapping: apigw.delete_base_path_mapping(
                    domainName=host, basePath=m["basePath"]))
    attempt(f"custom domain {host}", lambda: apigwmod.delete_custom_domain(apigw, host))

    # The api goes before the plan that meters it. A usage plan is refused while
    # any API stage is still associated with it, and deleting the api is what
    # clears that association — the other order can only ever fail.
    for api in _safe(lambda: apigw.get_rest_apis()["items"], []):
        if api["name"].startswith(SETUP_RESOURCES.prefix):
            attempt(f"rest api {api['name']}", lambda a=api: apigwmod.delete_api(apigw, a["id"]))

    for plan in _safe(lambda: apigw.get_usage_plans()["items"], []):
        if plan["name"].startswith(SETUP_RESOURCES.prefix):
            for key in _safe(lambda p=plan: apigw.get_usage_plan_keys(usagePlanId=p["id"])["items"], []):
                attempt(f"usage plan key {key['id']}",
                        lambda p=plan, k=key: apigwmod.delete_usage_plan_key(
                            apigw, plan_id=p["id"], key_id=k["id"]))
            attempt(f"usage plan {plan['name']}",
                    lambda p=plan: apigwmod.delete_usage_plan(apigw, plan_id=p["id"]))

    for key in _safe(lambda: apigw.get_api_keys()["items"], []):
        if key["name"].startswith(SETUP_RESOURCES.prefix):
            attempt(f"api key {key['name']}", lambda k=key: apigwmod.delete_api_key(apigw, k["id"]))


def delete_state_machines(session):
    sfn = session.client("stepfunctions")
    for machine in _safe(lambda: sfn.list_state_machines()["stateMachines"], []):
        if machine["name"].startswith(SETUP_RESOURCES.prefix):
            attempt(f"state machine {machine['name']}",
                    lambda m=machine: sfnmod.delete_state_machine(sfn, m["stateMachineArn"]))


def delete_distributions(session, domain):
    """Both together. Disabling one takes about twenty minutes to reach the
    edge, and doing them in turn would cost that twice.

    Only the enclave's own, matched by the names they answer for. An account
    may well have distributions of its own, and this is the step that cannot be
    undone by re-running anything.
    """
    cf = session.client("cloudfront")
    ours = {naming.dashboard_host(domain), naming.proof_host(domain)}
    items, skipped = [], []
    for page in cf.get_paginator("list_distributions").paginate():
        for item in page.get("DistributionList", {}).get("Items", []):
            aliases = set((item.get("Aliases") or {}).get("Items") or [])
            (items if aliases & ours else skipped).append(item)

    for item in skipped:
        print(f"   leaving {item['Id']} alone; it serves {sorted(set((item.get('Aliases') or {}).get('Items') or [])) or 'no enclave name'}")
    if not items:
        print("   (none of the enclave's own)")
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


def delete_origin_access_controls(session):
    """A step of its own, because they outlive the distributions that used them.

    A bring-up that died before creating any distribution still leaves these
    behind, so this cannot sit behind whether there were distributions to
    remove — which is the case that leaves them stranded.
    """
    cf = session.client("cloudfront")
    found_any = False
    for page in _safe(lambda: list(cf.get_paginator("list_origin_access_controls").paginate()), []):
        for found in page.get("OriginAccessControlList", {}).get("Items", []):
            if naming.is_ours(found["Name"]):
                found_any = True
                attempt(f"origin access control {found['Name']}",
                        lambda i=found["Id"]: cdnmod.delete_origin_access_control(cf, i))
    if not found_any:
        print("   (none of the enclave's own)")


def delete_certificates(session, domain):
    """After the distributions: ACM refuses to delete one still in use."""
    acm = session.client("acm")
    wanted = {naming.dashboard_host(domain), naming.proof_host(domain),
              naming.apply_host(domain)}
    for page in acm.get_paginator("list_certificates").paginate():
        for certificate in page["CertificateSummaryList"]:
            if certificate["DomainName"] in wanted:
                _delete_certificate_when_released(acm, certificate)


def _delete_certificate_when_released(acm, certificate):
    """Retried, because a distribution releases its certificate long after it
    has itself been deleted. ACM answers ResourceInUseException in the gap."""
    name, arn = certificate["DomainName"], certificate["CertificateArn"]
    for remaining in range(CERTIFICATE_RELEASE_ATTEMPTS, 0, -1):
        try:
            acmmod.delete_certificate(acm, arn)
            print(f"   deleted certificate for {name}")
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
                print(f"   COULD NOT delete certificate for {name}: {exc}")
                return
            if remaining == 1:
                print(f"   certificate for {name} is still in use; re-run unseal.py to finish")
                return
            print(f"   certificate for {name} still in use, waiting for CloudFront to release it")
            time.sleep(CERTIFICATE_RELEASE_INTERVAL)


def delete_buckets(session, account):
    s3 = session.client("s3")
    for bucket in (naming.proof_bucket_name(account), naming.dashboard_bucket_name(account)):
        attempt(f"bucket {bucket}", lambda b=bucket: s3mod.delete_bucket(s3, b))


def delete_zone(session, domain):
    """Only zones this program created, identified by their creation stamp.

    A domain that has ever been registered here already has a zone, and it is
    the one holding whatever mail and records the owner set up. Matching on the
    domain name alone would take that one.
    """
    r53 = session.client("route53")
    named = [z for z in _safe(lambda: r53.list_hosted_zones()["HostedZones"], [])
             if z["Name"].rstrip(".") == domain]
    ours = [z for z in named if naming.is_ours(z.get("CallerReference"))]

    for zone in named:
        if zone not in ours:
            print(f"   leaving {zone['Id'].split('/')[-1]} alone; not created by enclavize")
    if not ours:
        print("   (no hosted zone of the enclave's own)")
        return

    # delete_zone empties the zone first; the apex NS and SOA go with it.
    for zone in ours:
        zone_id = zone["Id"].split("/")[-1]
        attempt(f"hosted zone {zone_id}", lambda z=zone_id: dnsmod.delete_zone(r53, z))


def delete_identities(session):
    """Swept by prefix rather than by a list of names.

    Two roles carry an instance profile, not one, and a role inside a profile
    cannot be deleted — so profiles go first, and every one of them. Sweeping
    also means a name added to either phase's config is removed here without
    this function having to learn about it.
    """
    iam = session.client("iam")
    prefix = RESOURCES.prefix

    for page in iam.get_paginator("list_instance_profiles").paginate():
        for found in page["InstanceProfiles"]:
            if found["InstanceProfileName"].startswith(prefix):
                attempt(f"instance profile {found['InstanceProfileName']}",
                        lambda n=found["InstanceProfileName"]: iammod.delete_instance_profile(iam, name=n))

    for page in iam.get_paginator("list_roles").paginate():
        for found in page["Roles"]:
            if found["RoleName"].startswith(prefix):
                attempt(f"role {found['RoleName']}",
                        lambda r=found["RoleName"]: iammod.delete_role(iam, role=r))

    for page in iam.get_paginator("list_users").paginate():
        for found in page["Users"]:
            if found["UserName"].startswith(prefix):
                attempt(f"user {found['UserName']}",
                        lambda u=found["UserName"]: iammod.delete_user(iam, user=u))

    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for found in page["Policies"]:
            if found["PolicyName"].startswith(prefix):
                attempt(f"policy {found['PolicyName']}",
                        lambda a=found["Arn"]: iammod.delete_policy(iam, policy_arn=a))


def unlock_console(session, account):
    signin = session.client("signin", region_name=signinmod.WRITE_REGION)
    statements = _safe(lambda: signinmod.list_statements(signin), [])
    if not statements:
        print("   (no sign-in statements)")
    for statement in statements:
        sid = signinmod.statement_id(statement)
        attempt(f"sign-in statement {sid}",
                lambda s=sid: signinmod.disable_lock(signin, account_id=account, statement_id=s))


def delete_anchor_vpcs(session):
    ec2 = session.client("ec2")
    for vpc in _safe(lambda: ec2.describe_vpcs(
            Filters=[{"Name": "tag:Name", "Values": [RESOURCES.signin_lock_vpc_tag]}])["Vpcs"], []):
        attempt(f"anchor vpc {vpc['VpcId']}", lambda v=vpc: ec2mod.delete_vpc(ec2, v["VpcId"]))


def everything(session, account: str, domain: str, *, after_instances=None):
    """Every step, in the order the dependencies allow.

    `after_instances` is where an application's own teardown belongs: after the
    instances, because it cannot remove one enclavize launched and its security
    groups are held until those are gone — and before the hosted zone, because
    an application usually has records in it to tidy.
    """
    step("instances")
    terminate_instances(session)

    if after_instances is not None:
        after_instances()

    step("the apply API")
    delete_apply_api(session, domain)

    step("the state machine")
    delete_state_machines(session)

    step("the distributions")
    delete_distributions(session, domain)

    step("the origin access controls")
    delete_origin_access_controls(session)

    step("the buckets")
    delete_buckets(session, account)

    step("the hosted zone")
    delete_zone(session, domain)

    step("the identities")
    delete_identities(session)

    step("the console lock")
    unlock_console(session, account)

    step("the anchor VPC")
    delete_anchor_vpcs(session)

    # Last of the deletions: CloudFront hands a certificate back well after the
    # distribution using it is gone, so everything independent of ACM happens
    # first and this waits out whatever is left.
    step("the certificate")
    delete_certificates(session, domain)

    step("the go flag")
    attempt(RESOURCES.go_param,
            lambda: ssmmod.delete_parameter(session.client("ssm"), RESOURCES.go_param))


def report(session, account: str, domain: str) -> list:
    """Print what survived, and hand it back so a caller can act on it."""
    remaining = still_standing(session, account, domain)
    print("\n== still standing")
    if remaining:
        for item in remaining:
            print(f"   {item}")
        print("\n   Remove these before the next run; preflight will refuse until it is clean.")
    else:
        print("   nothing. The account is ready for another run.")
    return remaining



def send_domain_back(session, domain, target):
    """The half of a transfer this account can perform. The other half —
    accepting it — has to happen on the spare account."""
    response = session.client("route53domains", region_name=domainsmod.REGION) \
        .transfer_domain_to_another_aws_account(DomainName=domain, AccountId=target)
    print(f"\n== {domain} offered to {target}")
    print(f"   password: {response['Password']}")
    print("   Accept it from that account within three days, or AWS cancels the transfer:")
    print("     aws route53domains accept-domain-transfer-from-another-aws-account \\")
    print(f"       --domain-name {domain} --password '{response['Password']}' --region us-east-1")


def still_standing(session, account: str, domain: str) -> list:
    """Everything of the enclave's that is still standing.

    One description, used both by the teardown to report what it failed to
    remove and by preflight to refuse a cycle that would trip over it. Two
    descriptions drift, and they drift in the direction that matters: a
    teardown saying all-clear while preflight refuses, or the reverse.

    Ownership is judged the way each service allows — a creation stamp where
    the resource carries one, the resource prefix where it does not — never by
    the domain alone, because an account that has registered the domain already
    has a zone holding whatever its owner set up.
    """
    found = []

    for statement in _safe(
        lambda: signinmod.list_statements(
            session.client("signin", region_name=signinmod.WRITE_REGION)), []):
        found.append(f"sign-in statement {signinmod.statement_id(statement)}")

    iam = session.client("iam")
    for kind, call, key in (
        ("role", lambda: iam.list_roles()["Roles"], "RoleName"),
        ("user", lambda: iam.list_users()["Users"], "UserName"),
        ("instance profile", lambda: iam.list_instance_profiles()["InstanceProfiles"],
         "InstanceProfileName"),
        ("policy", lambda: iam.list_policies(Scope="Local")["Policies"], "PolicyName"),
    ):
        found += [f"{kind} {item[key]}" for item in _safe(call, [])
                  if item[key].startswith(RESOURCES.prefix)]

    s3 = session.client("s3")
    found += [f"bucket {b['Name']}" for b in _safe(lambda: s3.list_buckets()["Buckets"], [])
              if b["Name"] in (naming.proof_bucket_name(account),
                               naming.dashboard_bucket_name(account))]

    enclave_hosts = {naming.dashboard_host(domain), naming.proof_host(domain),
                     naming.apply_host(domain)}
    acm = session.client("acm")
    for page in _safe(lambda: list(acm.get_paginator("list_certificates").paginate()), []):
        found += [f"certificate {c['DomainName']}" for c in page["CertificateSummaryList"]
                  if c["DomainName"] in enclave_hosts]

    cf = session.client("cloudfront")
    for page in _safe(lambda: list(cf.get_paginator("list_distributions").paginate()), []):
        for item in page.get("DistributionList", {}).get("Items", []):
            if set((item.get("Aliases") or {}).get("Items") or []) & enclave_hosts:
                found.append(f"distribution {item['Id']}")
    for page in _safe(
            lambda: list(cf.get_paginator("list_origin_access_controls").paginate()), []):
        found += [f"origin access control {o['Name']}"
                  for o in page.get("OriginAccessControlList", {}).get("Items", [])
                  if naming.is_ours(o["Name"])]

    r53 = session.client("route53")
    found += [f"hosted zone {z['Id'].split('/')[-1]}"
              for z in _safe(lambda: r53.list_hosted_zones()["HostedZones"], [])
              if z["Name"].rstrip(".") == domain and naming.is_ours(z.get("CallerReference"))]

    apigw = session.client("apigateway")
    found += [f"rest api {a['name']}" for a in _safe(lambda: apigw.get_rest_apis()["items"], [])
              if a["name"].startswith(SETUP_RESOURCES.prefix)]
    found += [f"custom domain {d['domainName']}"
              for d in _safe(lambda: apigw.get_domain_names()["items"], [])
              if d["domainName"] in enclave_hosts]
    # Neither is reachable from outside, and neither costs anything — but a plan
    # left behind is a teardown that did not finish, and this survey is the only
    # thing that would say so.
    found += [f"usage plan {p['name']}"
              for p in _safe(lambda: apigw.get_usage_plans()["items"], [])
              if p["name"].startswith(SETUP_RESOURCES.prefix)]
    found += [f"api key {k['name']}" for k in _safe(lambda: apigw.get_api_keys()["items"], [])
              if k["name"].startswith(SETUP_RESOURCES.prefix)]

    found += [f"state machine {m['name']}" for m in _safe(
        lambda: session.client("stepfunctions").list_state_machines()["stateMachines"], [])
        if m["name"].startswith(SETUP_RESOURCES.prefix)]

    ec2 = session.client("ec2")
    for reservation in _safe(lambda: ec2.describe_instances(Filters=[
        {"Name": "tag:Name", "Values": [f"{RESOURCES.prefix}*"]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]},
    ])["Reservations"], []):
        found += [f"instance {i['InstanceId']}" for i in reservation["Instances"]]
    found += [f"anchor vpc {v['VpcId']}" for v in _safe(lambda: ec2.describe_vpcs(Filters=[
        {"Name": "tag:Name", "Values": [RESOURCES.signin_lock_vpc_tag]}])["Vpcs"], [])]

    if _safe(lambda: session.client("ssm").get_parameter(
            Name=RESOURCES.go_param), None):
        found.append(f"go flag {RESOURCES.go_param}")

    return found
