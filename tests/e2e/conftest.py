"""The end-to-end run: gates, the profile, and the rescue credentials.

Three gates, because these tests drive a real workflow against a real account
and every one of them is destructive:

- `ENCLAVIZE_E2E=1`, or the stages are not collected at all
- the account answering STS must be in `ENCLAVIZE_TEST_ACCOUNTS`
- the credentials must survive the seal and be able to undo it: root, or an IAM
  user with no permissions boundary. A boundary-carrying principal is fenced off
  from the enclave identities and the sign-in lock by design, so it could not
  close the loop and the account would be spent after one run.

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
    allowed_accounts,
    caller_problems,
    caller_workflow_text,
    derive_caller,
    load_profile,
    unfit_to_unseal,
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
def identity():
    """Who the suite is acting as, gated before anything runs.

    One STS call: the account and the ARN are both wanted, and both come back
    together.
    """
    allowed = allowed_accounts()
    if not allowed:
        pytest.fail("ENCLAVIZE_TEST_ACCOUNTS must list the accounts these tests may touch")

    answer = boto3.client("sts", region_name=REGION).get_caller_identity()
    if answer["Account"] not in allowed:
        pytest.fail(
            f"refusing to run: account {answer['Account']} is not in ENCLAVIZE_TEST_ACCOUNTS. "
            "These tests seal and then dismantle a real account."
        )
    problem = unfit_to_unseal(answer["Arn"], REGION)
    if problem:
        pytest.fail(f"refusing to run: {problem}")
    return answer


@pytest.fixture(scope="session")
def account_id(identity):
    return identity["Account"]


@pytest.fixture(scope="session")
def rescue(account_id):
    """The way-back-in session. Every call it makes happens after the console
    lock, which is itself the evidence that sign-in policies never touch SigV4."""
    return boto3.Session(region_name=REGION)


@pytest.fixture(scope="session")
def caller_arn(identity):
    """Root and an IAM user can see different things — notably, only root can
    enumerate root's access keys."""
    return identity["Arn"]


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
