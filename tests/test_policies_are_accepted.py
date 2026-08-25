"""Every policy document, put into IAM rather than only inspected.

test_policies.py asserts what the documents *say*; this asserts IAM will take
them. The two catch different things — a resource that is not a valid ARN reads
fine as data and is rejected outright by IAM, which would fail a real run at the
first step. moto validates document structure, so it catches that here for free.
"""

import json

import boto3
import pytest
from constants import ACCOUNT_ID, GO_PARAM, REGION
from moto import mock_aws

from enclavize.logic import policies

PROOF = f"enclavize-proof-{ACCOUNT_ID}"
DASHBOARD = f"enclavize-dashboard-{ACCOUNT_ID}"
BOUNDARY_ARN = f"arn:aws:iam::{ACCOUNT_ID}:policy/enclavize-deploy-boundary"


def boundary_document(protected=None):
    return policies.deploy_boundary_policy(
        account_id=ACCOUNT_ID, region=REGION, resource_prefix="enclavize-",
        proof_bucket=PROOF, dashboard_bucket=DASHBOARD, domain="example.com",
        hosted_zone_id="Z1EXAMPLE", state_machine="enclavize-deploy", protected=protected,
    )


@pytest.fixture
def iam():
    with mock_aws():
        yield boto3.client("iam", region_name=REGION)


def inline_documents():
    """Every document enclavize attaches to a principal it creates."""
    return {
        "event-reader": policies.event_reader_policy(),
        "starter": policies.starter_policy(
            region=REGION, account_id=ACCOUNT_ID, go_param=GO_PARAM, proof_bucket=PROOF
        ),
        "console-self-service": policies.console_self_service_policy(account_id=ACCOUNT_ID),
        "deploy-role": policies.deploy_role_policy(boundary_arn=BOUNDARY_ARN),
        "pass-role": policies.pass_role_policy(account_id=ACCOUNT_ID, role_name="enclavize-deploy"),
    }


@pytest.mark.parametrize("name", sorted(inline_documents()))
def test_iam_accepts_every_inline_policy(iam, name):
    iam.create_user(UserName="probe")
    iam.put_user_policy(
        UserName="probe", PolicyName=name, PolicyDocument=json.dumps(inline_documents()[name])
    )


def test_iam_accepts_the_permission_boundary(iam):
    document = boundary_document()
    iam.create_policy(PolicyName="enclavize-deploy-boundary", PolicyDocument=json.dumps(document))


def test_iam_accepts_the_trust_policies(iam):
    for name, trust in (
        ("ec2", policies.EC2_TRUST),
        ("sfn", policies.service_trust("states.amazonaws.com")),
        ("apigw", policies.service_trust("apigateway.amazonaws.com")),
    ):
        iam.create_role(RoleName=f"probe-{name}", AssumeRolePolicyDocument=json.dumps(trust))


def test_s3_accepts_the_cloudfront_bucket_policy():
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=PROOF)
        s3.put_bucket_policy(
            Bucket=PROOF,
            Policy=json.dumps(
                policies.cloudfront_read_bucket_policy(
                    bucket=PROOF, distribution_arn=f"arn:aws:cloudfront::{ACCOUNT_ID}:distribution/E1"
                )
            ),
        )


def test_every_resource_is_a_valid_arn_or_a_wildcard():
    """The specific mistake above: a policy variable used where an ARN belongs."""
    documents = list(inline_documents().values()) + [boundary_document()]
    for document in documents:
        for statement in document["Statement"]:
            resource = statement["Resource"]
            for value in [resource] if isinstance(resource, str) else resource:
                assert value == "*" or value.startswith("arn:"), value
