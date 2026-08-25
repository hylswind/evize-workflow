"""The statement is the signed artefact, so its exact shape is the contract."""

import json

import pytest
from constants import ACCOUNT_ID, DOMAIN, REPO_ID, STATEMENT_KEYS

from enclavize.logic import statement as st


def build(**overrides):
    kwargs = dict(
        account_id=ACCOUNT_ID,
        domain=DOMAIN,
        start=1700000000,
        hold_seconds=900,
        repo_id=REPO_ID,
        bypasses=st.build_bypasses(event_check=False, domain_transfer=False),
    )
    kwargs.update(overrides)
    return st.build_statement(**kwargs)


def test_key_order_is_fixed():
    assert list(build().keys()) == STATEMENT_KEYS


def test_key_order_survives_serialisation():
    text = st.serialise(build())
    assert list(json.loads(text).keys()) == STATEMENT_KEYS


def test_a_clean_run_is_not_debug():
    result = build()
    assert result["debug"] is False
    assert result["bypasses"] == {"eventCheck": False, "domainTransfer": False}


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        ({"event_check": True, "domain_transfer": False}, {"eventCheck": True, "domainTransfer": False}),
        ({"event_check": False, "domain_transfer": True}, {"eventCheck": False, "domainTransfer": True}),
        ({"event_check": True, "domain_transfer": True}, {"eventCheck": True, "domainTransfer": True}),
    ],
)
def test_any_bypass_makes_the_run_debug(kwargs, expected):
    result = build(bypasses=st.build_bypasses(**kwargs))
    assert result["debug"] is True
    assert result["bypasses"] == expected


def test_debug_cannot_be_passed_in():
    # debug is derived, so a caller cannot claim a clean run while bypassing.
    with pytest.raises(TypeError):
        st.build_statement(
            account_id=ACCOUNT_ID,
            domain=DOMAIN,
            start=1,
            hold_seconds=900,
            repo_id=REPO_ID,
            bypasses={},
            debug=False,
        )


def test_an_unknown_bypass_is_rejected():
    # A typo'd key would otherwise be silently dropped and read as a clean run.
    with pytest.raises(ValueError, match="unknown bypass"):
        build(bypasses={"eventChekc": True})


def test_a_missing_bypass_key_defaults_to_false():
    result = build(bypasses={"eventCheck": True})
    assert result["bypasses"] == {"eventCheck": True, "domainTransfer": False}


def test_numbers_are_coerced_because_workflow_inputs_arrive_as_strings():
    result = build(start="1700000000", hold_seconds="900", repo_id="42")
    assert result["start"] == 1700000000
    assert result["holdSeconds"] == 900
    assert result["repoID"] == 42


def test_write_and_digest_agree_with_the_file_on_disk(tmp_path):
    path = tmp_path / "statement.json"
    st.write_statement(path, build())
    assert path.read_text(encoding="utf-8") == st.serialise(build())

    import hashlib

    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    assert st.digest_file(path) == f"sha256:{expected}"


def test_digest_is_prefixed_the_way_attestation_subjects_are(tmp_path):
    path = tmp_path / "statement.json"
    st.write_statement(path, build())
    digest = st.digest_file(path)
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
