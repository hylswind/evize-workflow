"""Stage 2: what the sealed account built for itself, with nobody watching.

Runs against a live sealed account and needs nothing from stage 1 beyond the
statement, so it can be re-run on its own while iterating.

The single strongest assertion here is that `dashboard.{domain}` answers at all:
that requires the registrar to have been repointed, a certificate to have been
issued through DNS validation, and a distribution to have deployed — none of
which any offline test can reach, and all of which happen inside an account no
human can log into.

That is an assertion, not the wait. Waiting on it would make this suite depend
on a resolver and a CDN to learn something the account can be asked directly.
"""

import json

import pytest
from botocore.exceptions import ClientError
from harness import STATE_FILE, dig, fetch, poll, verify_attestation

from enclavize.aws import dns as dnsmod
from enclavize.aws import domains as domainsmod
from enclavize.aws import s3 as s3mod
from enclavize.logic import naming
from setup import apply as setup_apply
from setup import config as setup_config
from workflow import config as workflow_config

pytestmark = pytest.mark.e2e

RESOURCES = workflow_config.RESOURCES
SETUP_RESOURCES = setup_config.RESOURCES


@pytest.fixture(scope="session")
def state():
    """What stage 1 recorded, or the last successful run if it did not."""
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    pytest.fail(
        "no .e2e-state.json — run test_1_seal.py first, or set ENCLAVIZE_E2E_RUN_ID "
        "and run it to attach to an existing run"
    )


@pytest.fixture(scope="session", autouse=True)
def status(rescue, account_id, profile):
    """Block until the bring-up has actually finished.

    Read from the bucket rather than from the public name. This suite holds
    credentials; an operator does not, and conflating the two makes the wait
    depend on DNS and a CDN, neither of which has anything to say about whether
    the account is ready. Whether the public path works is asserted separately,
    where a failure means what it says.

    The wait ends only once the instance has gone too. `complete` is written
    while it is still shutting itself down, and this suite moves on to stage 3
    the moment the wait returns — far quicker than the person the ordering was
    written for.

    Autouse because every assertion in this file needs the bring-up finished,
    and without it a `-k` selecting one test would race the account.
    """
    bucket = naming.dashboard_bucket_name(account_id)
    s3_client, ec2_client = rescue.client("s3"), rescue.client("ec2")

    def finished():
        document = json.loads(s3mod.get_bytes(s3_client, bucket=bucket,
                                              key=setup_config.STATUS_KEY))
        if document.get("state") != "complete":
            return None
        live = [
            instance
            for reservation in ec2_client.describe_instances(
                Filters=[{"Name": "tag:Name", "Values": [RESOURCES.instance_name_tag]},
                         {"Name": "instance-state-name", "Values": ["pending", "running"]}],
            )["Reservations"]
            for instance in reservation["Instances"]
        ]
        return document if not live else None

    return poll(finished, timeout=profile.timeout("bringup"), interval=30,
                what="the bring-up to finish and the setup instance to go")


@pytest.fixture(scope="session")
def zone_id(rescue, profile):
    zones = rescue.client("route53").list_hosted_zones_by_name(DNSName=profile.domain)["HostedZones"]
    match = [z for z in zones if z["Name"].rstrip(".") == profile.domain]
    assert match, f"no hosted zone for {profile.domain}"
    return match[0]["Id"].split("/")[-1]


# --- the dashboard --------------------------------------------------------


def test_the_bring_up_finished(status, profile):
    assert status["state"] == "complete"
    assert status["domain"] == profile.domain


def test_the_two_parallel_phases_met(status):
    """The workflow and the setup program never talk. They agree on a bucket
    name derived from the account id, and one polls for the other to create it.
    Anything other than 'published' means that rendezvous failed."""
    assert status["proof"] == "published"


def test_the_dashboard_is_reachable_from_outside(profile):
    """Asserted apart from the wait above, which reads the bucket directly.

    A failure here is about the public path — DNS, the certificate, the CDN —
    and says so, instead of looking like an account that never finished.
    """
    code, body = fetch(f"https://{naming.dashboard_host(profile.domain)}/{setup_config.STATUS_KEY}")
    assert code == 200
    assert json.loads(body)["state"] == "complete", (
        "the bucket says complete but the CDN is serving something older"
    )


def test_the_dashboard_serves_its_static_page(profile):
    code, body = fetch(f"https://{naming.dashboard_host(profile.domain)}/")
    assert code == 200
    assert b"status.json" in body or b"<html" in body.lower()


# --- the proof ------------------------------------------------------------


def test_the_published_statement_is_byte_for_byte_the_signed_one(state, profile):
    code, body = fetch(f"https://{naming.proof_host(profile.domain)}/{setup_config.STATEMENT_KEY}")
    assert code == 200
    assert json.loads(body) == state["statement"]


def test_the_proof_site_serves_the_statement_at_its_root(profile):
    """The distribution's default root object, so the bare name is enough."""
    code, body = fetch(f"https://{naming.proof_host(profile.domain)}/")
    assert code == 200
    assert json.loads(body)["accountID"]


def test_the_published_pair_verifies_on_its_own(state, profile, tmp_path):
    """The real end-user path: the two files the account publishes, checked
    against each other with no call to GitHub at all. If this works, the proof
    survives the caller repository being deleted."""
    statement = tmp_path / "statement.json"
    bundle = tmp_path / "bundle.jsonl"
    for path, key in ((statement, setup_config.STATEMENT_KEY), (bundle, setup_config.BUNDLE_KEY)):
        code, body = fetch(f"https://{naming.proof_host(profile.domain)}/{key}")
        assert code == 200, f"{key} is not published"
        path.write_bytes(body)

    assert verify_attestation(
        statement, caller=state["caller"],
        signer_workflow=state["signerWorkflow"], bundle=bundle,
    )


def test_nothing_inside_the_account_can_rewrite_the_proof(rescue):
    """The starter is the only identity that could write to the proof bucket,
    and the bring-up deletes it once the objects have landed."""
    with pytest.raises(ClientError) as caught:
        rescue.client("iam").get_user(UserName=RESOURCES.starter_user)
    assert caught.value.response["Error"]["Code"] == "NoSuchEntity"


# --- the domain -----------------------------------------------------------


def test_the_registrar_points_at_this_accounts_zone(rescue, profile, zone_id):
    registrar = {
        ns["Name"].rstrip(".").lower()
        for ns in rescue.client("route53domains", region_name=domainsmod.REGION)
        .get_domain_detail(DomainName=profile.domain)["Nameservers"]
    }
    zone = {ns.rstrip(".").lower()
            for ns in dnsmod.nameservers(rescue.client("route53"), zone_id)}
    assert registrar == zone


def test_the_mailbox_is_dead(profile, rescue, zone_id):
    """A null MX (RFC 7505) is what kills the account's email address, and with
    it the last human route back in: no mail means no password reset."""
    records = rescue.client("route53").list_resource_record_sets(
        HostedZoneId=zone_id, StartRecordName=f"{profile.domain}.", StartRecordType="MX",
    )["ResourceRecordSets"]
    mx = [r for r in records
          if r["Name"].rstrip(".") == profile.domain and r["Type"] == "MX"]
    assert mx, "no MX record at the apex"
    assert [v["Value"] for v in mx[0]["ResourceRecords"]] == [setup_config.NULL_MX_VALUE]


def test_the_delegation_actually_landed(profile):
    """Asked of a public resolver, not of Route 53: the record existing in the
    zone means nothing until the world is being sent to that zone."""
    answers = dig(profile.domain, "MX", server="8.8.8.8")
    if not answers:
        pytest.skip("no public MX answer yet; delegation can take a while to propagate")
    assert any(answer.split()[-1] == "." for answer in answers), answers


# --- the apply machinery --------------------------------------------------


def test_the_apply_endpoint_has_its_own_name(rescue, profile):
    """Derived from the domain, because the generated execute-api name is
    computed on an instance that then terminates itself — inside an account with
    no console and no credentials. A value only that instance saw is a value
    nobody has."""
    host = naming.apply_host(profile.domain)
    domain_name = rescue.client("apigateway").get_domain_name(domainName=host)
    assert domain_name["endpointConfiguration"]["types"] == ["REGIONAL"]

    mappings = rescue.client("apigateway").get_base_path_mappings(domainName=host)["items"]
    assert [m["basePath"] for m in mappings] == [setup_config.APPLY_STAGE]


def test_the_apply_machinery_exists(rescue):
    iam = rescue.client("iam")
    for role in (SETUP_RESOURCES.apply_role, SETUP_RESOURCES.apply_sfn_role,
                 SETUP_RESOURCES.apply_api_role):
        iam.get_role(RoleName=role)
    machines = rescue.client("stepfunctions").list_state_machines()["stateMachines"]
    assert SETUP_RESOURCES.apply_state_machine in {m["name"] for m in machines}


def test_the_boundary_was_narrowed_to_the_enclaves_own_resources(rescue, profile, account_id, zone_id):
    """Created service-wide and tightened once the real resources exist, so an
    application can have an API and a distribution of its own.

    Compared against a document built here from the same inputs rather than
    against hand-written expectations: change the policy and this fails, instead
    of quietly asserting a shape that no longer ships.
    """
    iam = rescue.client("iam")
    arn = SETUP_RESOURCES.apply_boundary_arn(account_id)
    policy = iam.get_policy(PolicyArn=arn)["Policy"]
    live = iam.get_policy_version(
        PolicyArn=arn, VersionId=policy["DefaultVersionId"]
    )["PolicyVersion"]["Document"]

    # The API's id is read back off the custom domain rather than searched for:
    # that mapping is what actually serves apply.{domain}, so it names the API
    # the boundary has to protect.
    mappings = rescue.client("apigateway").get_base_path_mappings(
        domainName=naming.apply_host(profile.domain)
    )["items"]
    distributions = [
        item["Id"]
        for page in rescue.client("cloudfront").get_paginator("list_distributions").paginate()
        for item in page.get("DistributionList", {}).get("Items", [])
    ]

    expected = setup_apply.boundary_document(
        res=SETUP_RESOURCES, account_id=account_id, region="us-east-1",
        proof_bucket=naming.proof_bucket_name(account_id),
        dashboard_bucket=naming.dashboard_bucket_name(account_id),
        domain=profile.domain, hosted_zone_id=zone_id,
        protected={"api_id": mappings[0]["restApiId"], "distribution_ids": distributions},
    )
    assert normalised(live) == normalised(expected), (
        "the live boundary is not the tightened document this code builds"
    )


def normalised(document):
    """The same policy with every list in a stable order.

    IAM preserves what it was given, and the two distributions reach this
    comparison in whatever order CloudFront lists them rather than the order the
    bring-up wrote them. Order carries no meaning in a policy document, so a
    difference in it is not a difference worth failing on.
    """
    def fix(value):
        if isinstance(value, dict):
            return {k: fix(v) for k, v in sorted(value.items())}
        if isinstance(value, list):
            return sorted((fix(v) for v in value), key=repr)
        return value

    return fix(document)


def test_both_distributions_are_live(rescue):
    items = [
        item
        for page in rescue.client("cloudfront").get_paginator("list_distributions").paginate()
        for item in page.get("DistributionList", {}).get("Items", [])
    ]
    assert len(items) == 2, f"expected the dashboard and proof distributions, found {len(items)}"
    for item in items:
        assert item["Enabled"] is True
        assert item["Status"] == "Deployed"


# --- nothing left holding admin -------------------------------------------


def test_the_setup_instance_destroyed_itself(rescue):
    """The last act of the bring-up. Anything still running would be holding the
    admin role, which is the one credential inside the account that could undo
    all of this."""
    reservations = rescue.client("ec2").describe_instances(
        Filters=[{"Name": "tag:Name", "Values": [RESOURCES.instance_name_tag]}]
    )["Reservations"]
    states = {i["State"]["Name"] for r in reservations for i in r["Instances"]}
    assert states <= {"terminated", "shutting-down"}, states
