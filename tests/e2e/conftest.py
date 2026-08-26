"""The end-to-end run: gates, the profile, and the rescue credentials.

Three gates, because these tests drive a real workflow against a real account
and every one of them is destructive:

- `ENCLAVIZE_E2E=1`, or the stages are not collected at all
- the account answering STS must be in `ENCLAVIZE_TEST_ACCOUNTS`
- the caller must be *root* of that account — the rescue key. Only root can
  undo the sign-in lock and remove what the run created, so anything less means
  the loop cannot be closed and the account is spent.

test_profile.py is deliberately outside the gate: it needs no account and no
network, so it runs in an ordinary `pytest` and keeps the parameterisation
honest whether or not anyone has AWS set up.
"""

import os
import pathlib
import sys

import boto3
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from harness import (  # noqa: E402
    Profile,
    caller_problems,
    caller_workflow_text,
    derive_caller,
    load_profile,
)

REGION = os.environ.get("ENCLAVIZE_TEST_REGION", "us-east-1")

# Only the stages are gated. Ignoring at collection rather than skipping keeps
# them from being imported, so a missing profile cannot break an offline run.
collect_ignore_glob = (
    [] if os.environ.get("ENCLAVIZE_E2E") == "1"
    else ["test_1_*.py", "test_2_*.py", "test_3_*.py"]
)


@pytest.fixture(scope="session")
def profile() -> Profile:
    path = os.environ.get("ENCLAVIZE_E2E_PROFILE")
    if not path:
        pytest.fail(
            "ENCLAVIZE_E2E_PROFILE must point at a profile file. "
            "See tests/e2e/profiles/example.yml"
        )
    return load_profile(path)


@pytest.fixture(scope="session")
def account_id():
    """The account under test, checked twice before anything runs."""
    allowed = {a.strip() for a in os.environ.get("ENCLAVIZE_TEST_ACCOUNTS", "").split(",") if a.strip()}
    if not allowed:
        pytest.fail("ENCLAVIZE_TEST_ACCOUNTS must list the accounts these tests may touch")

    identity = boto3.client("sts", region_name=REGION).get_caller_identity()
    current, arn = identity["Account"], identity["Arn"]
    if current not in allowed:
        pytest.fail(
            f"refusing to run: account {current} is not in ENCLAVIZE_TEST_ACCOUNTS. "
            "These tests seal and then dismantle a real account."
        )
    if not arn.endswith(":root"):
        pytest.fail(
            f"refusing to run: {arn} is not the root user. The rescue root key is "
            "what makes this loop repeatable — without it the account cannot be "
            "unsealed and is spent after one run."
        )
    return current


@pytest.fixture(scope="session")
def rescue(account_id):
    """The rescue session. Every call it makes happens after the console lock,
    which is itself the evidence that sign-in policies never touch SigV4."""
    return boto3.Session(region_name=REGION)


@pytest.fixture(scope="session")
def caller(profile):
    """The caller's workflow, read rather than assumed.

    Failing here rather than at dispatch time is the whole point: a caller
    missing an input or a permission is a five-second failure now instead of a
    confusing one most of an hour in.
    """
    derived = derive_caller(caller_workflow_text(profile))
    problems = caller_problems(derived)
    if problems:
        pytest.fail(
            f"{profile.caller} cannot be driven by this suite:\n  - " + "\n  - ".join(problems)
        )
    return derived


@pytest.fixture(scope="session")
def apply_api_key():
    key = os.environ.get("ENCLAVIZE_APPLY_API_KEY", "")
    if not key:
        pytest.fail("ENCLAVIZE_APPLY_API_KEY must be set; it is never read from the profile")
    return key
