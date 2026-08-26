"""The reusable workflow, read as data.

Several properties here cannot be caught by any Python test but decide whether
the proof means anything — above all that the checked-out tree is enclavize's
own pinned commit rather than the caller's.
"""

import pathlib

import pytest
import yaml

from workflow import config

WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows/enclavize.yml"

# PyYAML reads a bare `on:` key as the boolean True (YAML 1.1 truthiness).
ON = True


@pytest.fixture(scope="module")
def workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def steps(workflow):
    return workflow["jobs"]["enclavize"]["steps"]


def raw():
    return WORKFLOW.read_text(encoding="utf-8")


def step_index(steps, needle):
    for index, step in enumerate(steps):
        haystack = " ".join(str(step.get(key, "")) for key in ("name", "run", "uses", "id"))
        if needle in haystack:
            return index
    raise AssertionError(f"no step matching {needle!r}")


def test_it_is_reusable_so_one_verifier_covers_every_caller(workflow):
    assert "workflow_call" in workflow[ON]


def test_the_inputs_are_the_five_the_run_expects(workflow):
    assert set(workflow[ON]["workflow_call"]["inputs"]) == {
        "domain",
        "start",
        "repo",
        "bypass_event_check",
        "bypass_domain_transfer",
    }


def test_both_bypasses_default_to_off(workflow):
    inputs = workflow[ON]["workflow_call"]["inputs"]
    for name in ("bypass_event_check", "bypass_domain_transfer"):
        assert inputs[name]["default"] is False
        assert inputs[name]["required"] is False


def test_the_secrets_are_the_five_the_run_needs(workflow):
    # No transfer account id: the accept API takes only a domain and password.
    assert set(workflow[ON]["workflow_call"]["secrets"]) == {
        "ROOT_KEY_ID",
        "ROOT_SECRET",
        "TRANSFER_PASSWORD",
        "APPLY_API_KEY",
        "CONSOLE_ZIP_PASSWORD",
    }


def test_the_permissions_are_what_signing_requires(workflow):
    assert workflow["permissions"] == {
        "id-token": "write",
        "attestations": "write",
        "contents": "read",
    }


def test_the_checkout_pins_enclavizes_own_commit(steps):
    """Otherwise the code that seals the account is not the attested code."""
    checkout = next(s for s in steps if str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["ref"] == "${{ job.workflow_sha }}"
    # Left to itself, checkout would take the caller's tree.
    assert "repository" in checkout["with"]
    assert checkout["with"]["repository"] == "${{ steps.self.outputs.repo }}"


def test_the_self_reference_is_refused_when_empty(steps):
    """An empty ref does not fail on its own: actions/checkout with no
    repository input falls back to github.repository, which inside a reusable
    workflow is the caller. The run would seal the account with the caller's
    code while the attestation named enclavize's — so the step checks."""
    step = next(s for s in steps if s.get("id") == "self")
    assert step["env"]["SELF_REF"] == "${{ job.workflow_ref }}"
    assert step["env"]["SELF_SHA"] == "${{ job.workflow_sha }}"
    for name in ("SELF_REF", "SELF_SHA"):
        assert f'test -n "${name}"' in step["run"], f"{name} is used without being checked"


def test_the_checkout_does_not_leave_a_token_behind(steps):
    checkout = next(s for s in steps if str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["persist-credentials"] is False


def test_the_run_is_told_which_commit_it_is(steps):
    seal = steps[step_index(steps, "python -u -m workflow")]
    assert seal["env"]["ENCLAVIZE_SELF_REF"] == "${{ job.workflow_ref }}"
    assert seal["env"]["ENCLAVIZE_SELF_SHA"] == "${{ job.workflow_sha }}"


def test_every_secret_reaches_the_run(steps):
    seal = steps[step_index(steps, "python -u -m workflow")]
    env = " ".join(seal["env"].values())
    for secret in ("ROOT_KEY_ID", "ROOT_SECRET", "TRANSFER_PASSWORD", "APPLY_API_KEY"):
        assert f"secrets.{secret}" in env


def test_the_zip_password_is_checked_before_the_account_is_touched(steps):
    # An empty password produces a readable archive, and that archive is
    # published as an artifact.
    assert step_index(steps, 'test -n "$ZIP_PASSWORD"') < step_index(steps, "python -u -m workflow")


def test_the_credentials_are_encrypted_before_anything_is_uploaded(steps):
    encrypt = step_index(steps, "7z a -mhe=on")
    upload = step_index(steps, "actions/upload-artifact")
    assert encrypt < upload


def test_the_plaintext_credentials_are_removed_after_encryption(steps):
    encrypt = steps[step_index(steps, "7z a -mhe=on")]
    assert "rm -f console.json" in encrypt["run"]
    # Runs even after a failure, or a half-sealed account leaves no way in.
    assert encrypt["if"] == "always()"


def test_the_statement_is_its_own_predicate(steps):
    attest = steps[step_index(steps, "actions/attest")]
    assert attest["with"]["subject-path"] == config.STATEMENT_FILE
    assert attest["with"]["predicate-path"] == config.STATEMENT_FILE
    assert attest["with"]["predicate-type"] == config.PREDICATE_TYPE


def test_proof_is_published_only_after_it_has_been_signed(steps):
    # The bundle does not exist until the attest step has run.
    assert step_index(steps, "actions/attest") < step_index(steps, "publish_proof")


def test_publishing_is_handed_the_bundle_the_attest_step_produced(steps):
    publish = steps[step_index(steps, "publish_proof")]
    assert "steps.attest.outputs.bundle-path" in publish["run"]


def test_only_the_statement_and_the_encrypted_credentials_are_uploaded(steps):
    uploaded = {s["with"]["path"] for s in steps if str(s.get("uses", "")).startswith("actions/upload-artifact")}
    assert uploaded == {config.STATEMENT_FILE, config.CONSOLE_ARCHIVE}


def test_the_credential_handover_file_is_never_uploaded():
    # It holds a live secret and exists only to reach the publish step.
    assert config.HANDOVER_FILE not in raw()
    gitignore = (WORKFLOW.parents[2] / ".gitignore").read_text(encoding="utf-8")
    assert config.HANDOVER_FILE in gitignore


def test_the_job_fits_inside_the_runner_ceiling(workflow):
    # The hold alone is fifteen minutes and history delivery can take twenty.
    assert workflow["jobs"]["enclavize"]["timeout-minutes"] <= 360
