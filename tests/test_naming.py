"""The names two parallel phases agree on without a channel between them."""

import re

from constants import ACCOUNT_ID, DOMAIN

from enclavize.logic import naming


def test_proof_bucket_is_derived_from_the_account_id():
    # Both phases compute this independently; nothing is passed between them.
    assert naming.proof_bucket_name(ACCOUNT_ID) == f"enclavize-proof-{ACCOUNT_ID}"


def test_bucket_names_avoid_dots():
    # A dotted bucket cannot be addressed over HTTPS virtual-hosted style
    # without certificate errors.
    for name in (naming.proof_bucket_name(ACCOUNT_ID), naming.dashboard_bucket_name(ACCOUNT_ID)):
        assert "." not in name


def test_bucket_names_are_legal_s3_names():
    pattern = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
    for name in (naming.proof_bucket_name(ACCOUNT_ID), naming.dashboard_bucket_name(ACCOUNT_ID)):
        assert pattern.match(name), name
        assert 3 <= len(name) <= 63


def test_proof_and_dashboard_buckets_are_distinct():
    assert naming.proof_bucket_name(ACCOUNT_ID) != naming.dashboard_bucket_name(ACCOUNT_ID)


def test_public_hosts_are_subdomains_of_the_main_domain():
    assert naming.dashboard_host(DOMAIN) == "dashboard.example.com"
    assert naming.proof_host(DOMAIN) == "proof.example.com"


def test_both_phases_import_the_same_function():
    """The handover breaks silently if the two phases ever diverge here."""
    from setup import config as setup_config
    from workflow import config as workflow_config

    assert workflow_config.proof_bucket_name is naming.proof_bucket_name
    assert setup_config.proof_bucket_name is naming.proof_bucket_name
    assert workflow_config.proof_bucket_name(ACCOUNT_ID) == setup_config.proof_bucket_name(ACCOUNT_ID)
