"""The only part of the end-to-end suite that can be tested without an account.

It is also the part most worth testing, because it is what makes the suite
usable against any caller and any application rather than one particular pair.
Deliberately outside the ENCLAVIZE_E2E gate: it runs in an ordinary `pytest`.
"""

import pytest
import yaml
from harness import (
    DEFAULT_TIMEOUTS,
    PREDICATE_TYPE,
    ProfileError,
    caller_problems,
    derive_caller,
    parse_profile,
)

from workflow import config as workflow_config

FULL = """
caller: acme/enclavize-caller
callerWorkflow: seal.yml
domain: Example.COM
rescueKeyId: AKIAEXAMPLE
transfer: real
app:
  repo: acme/application
  ref: v2
  url: https://app.example.com
  resultsUrl: https://app.example.com/results.json
  teardown: teardown.sh
timeouts:
  bringup: 60
"""

MINIMAL = """
caller: acme/enclavize-caller
domain: example.com
app:
  repo: acme/application
"""

GOOD_CALLER = """
name: enclavize this account
on:
  workflow_dispatch:
    inputs:
      domain: {required: true, type: string}
      start: {required: true, type: string}
      repo: {required: true, type: string}
      bypass_event_check: {type: boolean, default: false}
      bypass_domain_transfer: {type: boolean, default: false}
jobs:
  enclavize:
    permissions:
      id-token: write
      attestations: write
      contents: read
    uses: acme/enclavize-workflow/.github/workflows/enclavize.yml@0123456789abcdef0123456789abcdef01234567
    with:
      domain: ${{ inputs.domain }}
    secrets:
      ROOT_KEY_ID: ${{ secrets.ROOT_KEY_ID }}
      APPLY_API_KEY: ${{ secrets.APPLY_API_KEY }}
"""


def caller_yaml(**edits):
    """The good caller with one part replaced, so each test changes one thing."""
    doc = yaml.safe_load(GOOD_CALLER)
    job = doc["jobs"]["enclavize"]
    if "inputs" in edits:
        doc[True]["workflow_dispatch"]["inputs"] = edits["inputs"]
    if "permissions" in edits:
        job["permissions"] = edits["permissions"]
    if "uses" in edits:
        job["uses"] = edits["uses"]
    if edits.get("second_job"):
        doc["jobs"]["another"] = {"uses": "acme/other/.github/workflows/x.yml@main"}
    if edits.get("no_uses"):
        del job["uses"]
    return yaml.safe_dump(doc)


# --- the profile ----------------------------------------------------------


def test_a_full_profile_round_trips():
    profile = parse_profile(FULL)
    assert profile.caller == "acme/enclavize-caller"
    assert profile.caller_workflow == "seal.yml"
    assert profile.rescue_key_id == "AKIAEXAMPLE"
    assert profile.transfer == "real"
    assert profile.app.repo == "acme/application"
    assert profile.app.ref == "v2"
    assert profile.app.results_url == "https://app.example.com/results.json"
    assert profile.app.teardown == "teardown.sh"


def test_the_domain_is_normalised():
    """It is compared against what AWS reports, which is lowercase."""
    assert parse_profile(FULL).domain == "example.com"


def test_only_the_named_timeout_is_overridden():
    profile = parse_profile(FULL)
    assert profile.timeout("bringup") == 60
    assert profile.timeout("seal") == DEFAULT_TIMEOUTS["seal"]


def test_a_minimal_profile_is_enough():
    """Everything enclavize itself requires of an application is a repo. The
    rest describes what one particular application happens to do."""
    profile = parse_profile(MINIMAL)
    assert profile.caller_workflow == "enclavize.yml"
    assert profile.transfer == "bypass"
    assert profile.timeouts == DEFAULT_TIMEOUTS
    assert profile.app.url == ""
    assert profile.app.results_url == ""
    assert profile.app.teardown == ""


def test_bypass_is_the_default_because_real_consumes_a_pending_transfer():
    assert parse_profile(MINIMAL).bypass_domain_transfer is True
    assert parse_profile(FULL).bypass_domain_transfer is False


@pytest.mark.parametrize("field", ["caller", "domain", "app"])
def test_a_missing_required_field_names_itself(field):
    raw = yaml.safe_load(MINIMAL)
    del raw[field]
    with pytest.raises(ProfileError, match=field):
        parse_profile(yaml.safe_dump(raw))


def test_an_app_without_a_repo_is_rejected():
    with pytest.raises(ProfileError, match="app.repo"):
        parse_profile("caller: a/b\ndomain: example.com\napp:\n  url: https://x\n")


def test_an_unknown_transfer_mode_is_rejected():
    """Anything other than these two would silently become 'bypass' and seal an
    account that does not hold the domain."""
    with pytest.raises(ProfileError, match="transfer"):
        parse_profile(MINIMAL.replace("domain:", "transfer: maybe\ndomain:"))


def test_a_repo_that_is_not_owner_slash_name_is_rejected():
    with pytest.raises(ProfileError, match="owner/name"):
        parse_profile(MINIMAL.replace("acme/application", "application"))


# --- reading the caller ---------------------------------------------------


def test_the_signer_workflow_is_the_uses_line_without_its_ref():
    """This is what makes the suite caller-agnostic: the value gh needs is
    already written in the caller, so it is read rather than configured."""
    caller = derive_caller(GOOD_CALLER)
    assert caller.signer_workflow == "acme/enclavize-workflow/.github/workflows/enclavize.yml"
    assert caller.ref == "0123456789abcdef0123456789abcdef01234567"


def test_a_pinned_sha_is_told_apart_from_a_branch():
    assert derive_caller(GOOD_CALLER).pinned_to_a_commit is True
    assert derive_caller(caller_yaml(uses="acme/w/.github/workflows/e.yml@main")).pinned_to_a_commit is False


def test_the_dispatch_inputs_and_secrets_are_read():
    caller = derive_caller(GOOD_CALLER)
    assert "bypass_domain_transfer" in caller.inputs
    assert caller.secrets == {"ROOT_KEY_ID", "APPLY_API_KEY"}


def test_a_bare_on_key_is_still_found():
    """PyYAML reads `on:` as the boolean True, so a naive lookup finds nothing
    and every input looks missing."""
    assert derive_caller(GOOD_CALLER).inputs


def test_a_caller_that_calls_nothing_is_rejected():
    with pytest.raises(ProfileError, match="no job with a `uses:`"):
        derive_caller(caller_yaml(no_uses=True))


def test_a_caller_that_calls_two_workflows_is_rejected():
    """Which one signed the statement would be a guess, and the whole point of
    --signer-workflow is not guessing."""
    with pytest.raises(ProfileError, match="more than one"):
        derive_caller(caller_yaml(second_job=True))


def test_an_unpinned_uses_is_rejected():
    with pytest.raises(ProfileError, match="nothing pinned"):
        derive_caller(caller_yaml(uses="acme/w/.github/workflows/e.yml"))


# --- whether the caller can be driven -------------------------------------


def test_a_well_formed_caller_has_no_problems():
    assert caller_problems(derive_caller(GOOD_CALLER)) == []


def test_a_missing_dispatch_input_is_reported_by_name():
    inputs = yaml.safe_load(GOOD_CALLER)[True]["workflow_dispatch"]["inputs"]
    del inputs["bypass_domain_transfer"]
    problems = caller_problems(derive_caller(caller_yaml(inputs=inputs)))
    assert any("bypass_domain_transfer" in p for p in problems)


@pytest.mark.parametrize("dropped", ["id-token", "attestations", "contents"])
def test_a_missing_permission_is_reported(dropped):
    """A reusable workflow gets the intersection of its permissions and the
    caller's, so any of these missing means no signature — and a run that
    otherwise looks like it worked."""
    permissions = yaml.safe_load(GOOD_CALLER)["jobs"]["enclavize"]["permissions"]
    del permissions[dropped]
    problems = caller_problems(derive_caller(caller_yaml(permissions=permissions)))
    assert any(dropped in p for p in problems)


def test_every_problem_is_reported_at_once():
    """One failure per run of a two-hour suite would be a poor trade."""
    problems = caller_problems(derive_caller(caller_yaml(inputs={}, permissions={})))
    assert len(problems) > 1


# --- no retyped constants -------------------------------------------------


def test_the_predicate_type_comes_from_the_workflow_config():
    """Retyping it would let the suite keep passing against a predicate the
    workflow no longer emits."""
    assert PREDICATE_TYPE is workflow_config.PREDICATE_TYPE
