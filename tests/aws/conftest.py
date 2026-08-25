"""Real-account tests: the gate, the prefix, and the cleanup.

These create and destroy real resources. Two things keep that safe:

- nothing runs unless ENCLAVIZE_AWS_TEST=1 and the account answering STS is in
  ENCLAVIZE_TEST_ACCOUNTS, so a stray profile cannot point them at production
- every resource is named with a per-run prefix and deleted by that prefix,
  so runs cannot collide and leftovers are always identifiable

What is under test is enclavize/aws/*, never a step: a step only orders modules
and chooses credentials, which offline tests already pin.
"""

import os
import secrets

import boto3
import pytest

from workflow import config as workflow_config

REGION = os.environ.get("ENCLAVIZE_TEST_REGION", "us-east-1")

# Not collected at all unless asked for, so a plain `pytest` can never reach a
# real account. Ignoring at collection rather than skipping keeps these files
# from being imported, which also keeps them from shadowing anything.
collect_ignore_glob = [] if os.environ.get("ENCLAVIZE_AWS_TEST") == "1" else ["test_*.py"]


@pytest.fixture(scope="session")
def account_id():
    """The account under test, checked against the allow-list before anything runs."""
    allowed = {a.strip() for a in os.environ.get("ENCLAVIZE_TEST_ACCOUNTS", "").split(",") if a.strip()}
    if not allowed:
        pytest.fail("ENCLAVIZE_TEST_ACCOUNTS must list the accounts these tests may touch")
    current = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    if current not in allowed:
        pytest.fail(
            f"refusing to run: account {current} is not in ENCLAVIZE_TEST_ACCOUNTS. "
            "These tests create and delete real resources."
        )
    return current


@pytest.fixture(scope="session")
def session(account_id):
    return boto3.Session(region_name=REGION)


@pytest.fixture
def prefix():
    """A namespace for one test, so runs never collide and leftovers are obvious."""
    return f"t{secrets.token_hex(4)}-"


@pytest.fixture
def resources(prefix):
    return workflow_config.RESOURCES.with_prefix(prefix)


@pytest.fixture
def iam(session):
    return session.client("iam")


@pytest.fixture
def ec2(session):
    return session.client("ec2")


@pytest.fixture
def s3(session):
    return session.client("s3")


@pytest.fixture
def ssm(session):
    return session.client("ssm")


@pytest.fixture
def cloudtrail(session):
    return session.client("cloudtrail")


@pytest.fixture
def route53(session):
    return session.client("route53")


@pytest.fixture
def acm(session):
    return session.client("acm")


@pytest.fixture
def cloudfront(session):
    return session.client("cloudfront")


@pytest.fixture
def apigateway(session):
    return session.client("apigateway")


@pytest.fixture
def stepfunctions(session):
    return session.client("stepfunctions")


@pytest.fixture
def signin(session):
    # Sign-in policy writes are only accepted in us-east-1.
    return session.client("signin", region_name="us-east-1")
