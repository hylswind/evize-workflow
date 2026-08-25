"""The sealing sequence.

Steps hold no AWS usage of their own, so what is worth testing is the order and
the credential handover — both of which are the security properties. Every step
is replaced by a recorder.
"""

import json

import pytest
from constants import ACCOUNT_ID, APP_REPO, DOMAIN, REPO_ID, SELF_REPO, SELF_SHA

from workflow import __main__ as run_module
from workflow import config

BASE_ENV = {
    "ENCLAVIZE_ROOT_KEY": "AKIAROOT",
    "ENCLAVIZE_ROOT_SECRET": "rootsecret",
    "ENCLAVIZE_TRANSFER_PASSWORD": "transfer-pw",
    "ENCLAVIZE_DEPLOY_API_KEY": "deploy-key",
    "ENCLAVIZE_DOMAIN": DOMAIN,
    "ENCLAVIZE_START": "1700000000",
    "ENCLAVIZE_REPO": APP_REPO,
    "ENCLAVIZE_SELF_REF": f"{SELF_REPO}/.github/workflows/enclavize.yml@refs/heads/main",
    "ENCLAVIZE_SELF_SHA": SELF_SHA,
    "ENCLAVIZE_CALLER_REPO": "acme/caller",
}


def env(**overrides):
    merged = dict(BASE_ENV)
    merged.update(overrides)
    return {k: v for k, v in merged.items() if v is not None}


class FakeSession:
    def __init__(self, label, journal):
        self.label = label
        self.journal = journal

    def client(self, name, region_name=None):
        return f"{self.label}:{name}"


@pytest.fixture
def journal(monkeypatch, tmp_path):
    """Replace every step with a recorder and run in a scratch directory."""
    events = []
    monkeypatch.chdir(tmp_path)

    def session(access_key, secret_key, region=None, record=None):
        label = {"AKIAROOT": "root", "AKIAREAD": "reader", "AKIASTART": "starter"}.get(access_key, access_key)
        # Every session records its request ids, which is what lets the audit
        # tell the run's own calls from a person's.
        events.append(("session", label, record is not None))
        return FakeSession(label, events)

    monkeypatch.setattr(run_module.clients, "session", session)
    monkeypatch.setattr(run_module.github, "resolve_repo_id", lambda repo, token=None: REPO_ID)
    monkeypatch.setattr(run_module.sts, "account_id", lambda client: ACCOUNT_ID)

    def step(name, result=None):
        def recorder(*args, **kwargs):
            events.append((name, kwargs))
            return result

        return recorder

    monkeypatch.setattr(run_module, "assert_sole_root_key", step("sole_root_key"))
    monkeypatch.setattr(
        run_module.s1_identities, "create_identities",
        step("identities", {
            "instance_profile": "enclavize-admin",
            "reader_key": "AKIAREAD", "reader_secret": "readsecret",
            "starter_key": "AKIASTART", "starter_secret": "startsecret",
            "console_password": "Pw1!aaaaaaaa", "proof_bucket": f"enclavize-proof-{ACCOUNT_ID}",
        }),
    )
    monkeypatch.setattr(run_module.s3_domain_transfer, "accept", step("transfer"))
    monkeypatch.setattr(run_module.s4_lock_signin, "lock", step("lock", ("vpc-1", "stmt-1")))
    monkeypatch.setattr(run_module.s2_launch, "launch", step("launch", "i-1"))
    monkeypatch.setattr(run_module.s5_delete_root, "delete_root_key", step("delete_root"))
    monkeypatch.setattr(run_module.s6_hold, "wait", step("hold"))
    monkeypatch.setattr(run_module.s8_handover, "release", step("handover"))

    class Passing:
        ok = True

        def report(self):
            return "ok"

    monkeypatch.setattr(run_module.s7_event_check, "verify", step("event_check", Passing()))
    return events


def names(journal):
    return [entry[0] for entry in journal if entry[0] != "session"]


def run(**overrides):
    return run_module.run(run_module.RunConfig.from_env(env(**overrides)), log=lambda *_: None)


# --- ordering -------------------------------------------------------------


def test_the_reversible_steps_all_precede_the_irreversible_ones(journal):
    run()
    order = names(journal)
    # Accepting the transfer can fail on a wrong password; it must fail while
    # the account is still usable.
    assert order.index("transfer") < order.index("lock")
    assert order.index("transfer") < order.index("delete_root")


def test_the_instance_is_launched_before_the_root_key_is_deleted(journal):
    # Launching needs root, so this ordering is not a preference but a
    # requirement.
    run()
    order = names(journal)
    assert order.index("launch") < order.index("delete_root")


def test_the_full_order_is_what_the_seal_depends_on(journal):
    run()
    assert names(journal) == [
        "sole_root_key",
        "identities",
        "transfer",
        "lock",
        "launch",
        "delete_root",
        "hold",
        "event_check",
        "handover",
    ]


def test_the_account_is_handed_over_only_after_it_is_audited(journal):
    # Firing the go flag before the check would let the account start running
    # even though a human may have interfered.
    run()
    order = names(journal)
    assert order.index("event_check") < order.index("handover")


def test_history_is_given_time_to_settle_before_it_is_read(journal):
    run()
    order = names(journal)
    assert order.index("hold") < order.index("event_check")


# --- credentials ----------------------------------------------------------


def test_each_phase_uses_the_narrowest_identity_available(journal):
    run()
    sessions = [entry[1] for entry in journal if entry[0] == "session"]
    # Root seals; the reader audits; the starter hands over. Root's key is gone
    # before either of the others is used.
    assert sessions == ["root", "reader", "starter"]


def test_the_console_password_is_written_before_anything_can_fail(journal, tmp_path):
    run()
    order = names(journal)
    written = json.loads((tmp_path / config.CONSOLE_FILE).read_text())
    assert written["password"] == "Pw1!aaaaaaaa"
    assert written["signInUrl"] == f"https://{ACCOUNT_ID}.signin.aws.amazon.com/console"
    # Written before the account is sealed, so a later failure still leaves the
    # operator a way in.
    assert order.index("identities") == 1  # after the root-key check


# --- bypasses -------------------------------------------------------------


def test_a_clean_run_produces_a_statement_that_is_not_debug(journal, tmp_path):
    run()
    statement = json.loads((tmp_path / config.STATEMENT_FILE).read_text())
    assert statement["debug"] is False
    assert statement["bypasses"] == {"eventCheck": False, "domainTransfer": False}
    assert statement["accountID"] == ACCOUNT_ID
    assert statement["repoID"] == REPO_ID
    assert statement["domain"] == DOMAIN


def test_bypassing_the_event_check_skips_it_and_marks_the_statement(journal, tmp_path):
    run(ENCLAVIZE_BYPASS_EVENT_CHECK="true")
    assert "event_check" not in names(journal)
    statement = json.loads((tmp_path / config.STATEMENT_FILE).read_text())
    assert statement["debug"] is True
    assert statement["bypasses"]["eventCheck"] is True


def test_bypassing_the_transfer_skips_it_and_marks_the_statement(journal, tmp_path):
    run(ENCLAVIZE_BYPASS_DOMAIN_TRANSFER="1")
    assert "transfer" not in names(journal)
    statement = json.loads((tmp_path / config.STATEMENT_FILE).read_text())
    assert statement["debug"] is True
    assert statement["bypasses"]["domainTransfer"] is True


def test_a_failed_event_check_stops_the_run_before_handover(journal):
    class Failing:
        ok = False

        def report(self):
            return "someone else acted"

    run_module.s7_event_check.verify = lambda *a, **k: (journal.append(("event_check", {})), Failing())[1]

    with pytest.raises(SystemExit, match="someone else acted"):
        run()
    # The account must not start running itself when the seal is in doubt.
    assert "handover" not in names(journal)


# --- configuration --------------------------------------------------------


def test_a_start_in_the_future_is_rejected():
    with pytest.raises(ValueError, match="must be in the past"):
        run_module.RunConfig.from_env(env(ENCLAVIZE_START="99999999999"))


def test_a_non_numeric_start_is_rejected():
    with pytest.raises(ValueError, match="not a unix timestamp"):
        run_module.RunConfig.from_env(env(ENCLAVIZE_START="yesterday"))


@pytest.mark.parametrize("missing", ["ENCLAVIZE_ROOT_KEY", "ENCLAVIZE_DEPLOY_API_KEY", "ENCLAVIZE_REPO"])
def test_a_missing_requirement_is_named(missing):
    with pytest.raises(ValueError, match=missing):
        run_module.RunConfig.from_env(env(**{missing: None}))


def test_a_malformed_app_repo_is_rejected():
    # It reaches a shell command inside user-data.
    with pytest.raises(ValueError):
        run_module.RunConfig.from_env(env(ENCLAVIZE_REPO="not-a-repo"))


def test_enclavize_discovers_its_own_pinned_identity():
    # Inside a reusable workflow github.repository is the caller, so the sha to
    # clone can only come from job_workflow_ref/sha.
    cfg = run_module.RunConfig.from_env(env())
    assert cfg.self_repo == SELF_REPO
    assert cfg.self_sha == SELF_SHA
    assert cfg.caller_repo == "acme/caller"


def test_a_missing_self_ref_is_rejected():
    # Absent means this is not running as a reusable workflow, so the sha it
    # would clone is not the attested code.
    with pytest.raises(ValueError, match="ENCLAVIZE_SELF_REF is required"):
        run_module.RunConfig.from_env(env(ENCLAVIZE_SELF_REF=None))


def test_a_malformed_self_ref_is_rejected():
    with pytest.raises(ValueError, match="cannot parse job_workflow_ref"):
        run_module.RunConfig.from_env(env(ENCLAVIZE_SELF_REF="garbage@refs/heads/main"))


def test_a_self_sha_that_is_not_a_commit_is_rejected():
    with pytest.raises(ValueError, match="40-hex commit sha"):
        run_module.RunConfig.from_env(env(ENCLAVIZE_SELF_SHA="main"))


# --- handover to the publish step ----------------------------------------


def test_the_handover_file_carries_only_what_publishing_needs(tmp_path, capsys):
    result = {
        "proof_bucket": "enclavize-proof-1",
        "starter_key": "AKIASTART",
        "starter_secret": "startsecret",
        "region": "us-east-1",
    }
    path = tmp_path / "handover.json"

    run_module.write_publish_handover(path, result)

    written = json.loads(path.read_text())
    assert written == {
        "proofBucket": "enclavize-proof-1",
        "starterKey": "AKIASTART",
        "starterSecret": "startsecret",
        "region": "us-east-1",
    }


def test_the_starter_secret_is_masked_in_the_log(tmp_path, capsys):
    """It is generated at runtime, so GitHub does not know to redact it."""
    run_module.write_publish_handover(
        tmp_path / "h.json",
        {"proof_bucket": "b", "starter_key": "k", "starter_secret": "startsecret", "region": "us-east-1"},
    )
    assert "::add-mask::startsecret" in capsys.readouterr().out


def test_the_handover_file_is_not_world_readable(tmp_path):
    path = tmp_path / "handover.json"
    run_module.write_publish_handover(
        path, {"proof_bucket": "b", "starter_key": "k", "starter_secret": "s", "region": "us-east-1"}
    )
    assert oct(path.stat().st_mode)[-3:] == "600"


# --- the root key must be the only one ------------------------------------


class FakeIam:
    def __init__(self, *key_ids):
        self.key_ids = key_ids

    def list_access_keys(self):
        return {"AccessKeyMetadata": [{"AccessKeyId": k} for k in self.key_ids]}


def test_one_root_key_that_matches_is_accepted():
    run_module.assert_sole_root_key(FakeIam("AKIAROOT"), "AKIAROOT")


def test_a_second_root_key_stops_the_run():
    """The run deletes only the key it was given, so another would outlive the
    seal. Caught here rather than by the audit because the audit runs after the
    console is shut and root's key is already gone."""
    with pytest.raises(SystemExit, match="outlive the"):
        run_module.assert_sole_root_key(FakeIam("AKIAROOT", "AKIAOTHER"), "AKIAROOT")


def test_a_key_that_is_not_the_one_we_were_given_stops_the_run():
    with pytest.raises(SystemExit):
        run_module.assert_sole_root_key(FakeIam("AKIASOMETHINGELSE"), "AKIAROOT")


def test_the_check_runs_before_anything_irreversible(journal):
    run()
    order = names(journal)
    assert order.index("sole_root_key") < order.index("lock")
    assert order.index("sole_root_key") < order.index("delete_root")
