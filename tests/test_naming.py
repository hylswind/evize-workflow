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
    assert naming.apply_host(DOMAIN) == "apply.example.com"


def test_the_three_public_hosts_are_distinct():
    """They share one certificate and one hosted zone; a collision would have
    two of them fighting over the same record."""
    hosts = {naming.dashboard_host(DOMAIN), naming.proof_host(DOMAIN), naming.apply_host(DOMAIN)}
    assert len(hosts) == 3


def test_the_apply_endpoint_is_derivable_from_the_domain_alone():
    """The whole reason it exists. The generated execute-api name is computed on
    an instance that then terminates itself, inside an account with no console
    and no credentials — so a value only that instance saw is a value nobody
    has. This one needs no channel to reach the operator."""
    assert naming.apply_host(DOMAIN) == f"apply.{DOMAIN}"


def test_both_phases_import_the_same_function():
    """The handover breaks silently if the two phases ever diverge here."""
    from setup import config as setup_config
    from workflow import config as workflow_config

    assert workflow_config.proof_bucket_name is naming.proof_bucket_name
    assert setup_config.proof_bucket_name is naming.proof_bucket_name
    assert workflow_config.proof_bucket_name(ACCOUNT_ID) == setup_config.proof_bucket_name(ACCOUNT_ID)


def test_a_creation_stamp_says_this_program_made_it():
    """What a teardown goes on. An account that has registered the domain
    already has a hosted zone, and a name alone cannot tell it from ours."""
    stamp = naming.caller_reference(ACCOUNT_ID, "abc123")
    assert naming.is_ours(stamp)
    assert ACCOUNT_ID in stamp


def test_anything_else_is_left_alone():
    # What Route 53 puts on the zone it creates when a domain is registered.
    assert not naming.is_ours("RISWorkflow-RD:36a80f94-f7a9-4a0f-9f2d-8ef77e142c83")
    assert not naming.is_ours("")
    assert not naming.is_ours(None)


def test_two_runs_in_one_account_do_not_collide():
    """Origin access control names are unique per account and outlive the
    distributions using them, so the stamp has to differ run to run."""
    assert naming.caller_reference(ACCOUNT_ID, "aaa") != naming.caller_reference(ACCOUNT_ID, "bbb")
