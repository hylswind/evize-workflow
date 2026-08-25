"""The one place the two phases meet, exercised end to end in one account.

In production the workflow and the setup program run in parallel and cannot
talk. Here both halves are driven in sequence so the coordination itself can be
checked before an end-to-end run depends on it:

  setup creates the bucket -> the workflow waits, then uploads -> setup checks
  what landed and retires the writer.

The failure this is really guarding against is the bucket policy: attaching the
CDN with an explicit deny would lock out an upload that is still in flight, and
that only shows up when the two halves overlap.
"""

import json

import pytest
from botocore.exceptions import ClientError

from enclavize.aws import s3 as s3mod
from enclavize.logic import naming, policies
from setup import config as setup_config
from setup import proof
from workflow import config as workflow_config
from workflow import publish_proof

pytestmark = pytest.mark.aws


@pytest.fixture
def proof_bucket(s3, account_id, prefix):
    """A stand-in for the real proof bucket, named the same way but prefixed."""
    bucket = f"{prefix}{naming.proof_bucket_name(account_id)}"[:63]
    yield bucket
    try:
        s3mod.delete_bucket(s3, bucket)
    except ClientError:
        pass


@pytest.fixture
def artifacts(tmp_path):
    statement = tmp_path / workflow_config.STATEMENT_FILE
    bundle = tmp_path / workflow_config.BUNDLE_FILE
    statement.write_text(json.dumps({"accountID": "123456789012", "debug": True}), encoding="utf-8")
    # A stand-in bundle carrying the statement's digest, which is what the seal
    # step cross-checks.
    import hashlib

    digest = hashlib.sha256(statement.read_bytes()).hexdigest()
    bundle.write_text(json.dumps({"subject": [{"digest": {"sha256": digest}}]}), encoding="utf-8")
    return statement, bundle


def test_both_sides_derive_the_same_bucket_name(account_id):
    """There is no channel between them; the name is the whole agreement."""
    assert workflow_config.proof_bucket_name(account_id) == setup_config.proof_bucket_name(account_id)


def test_the_workflow_waits_for_the_bucket_then_publishes(s3, proof_bucket, artifacts, account_id):
    statement, bundle = artifacts

    # setup's first action
    s3mod.create_bucket(s3, proof_bucket, region="us-east-1")

    # the workflow, once it has signed
    published = publish_proof.upload(
        s3, bucket=proof_bucket, statement_path=statement, bundle_path=bundle,
        poll_max=60, interval=5,
    )

    assert published is True
    assert s3mod.object_exists(s3, bucket=proof_bucket, key=workflow_config.STATEMENT_FILE)
    assert s3mod.object_exists(s3, bucket=proof_bucket, key=workflow_config.BUNDLE_FILE)


def test_an_allow_only_bucket_policy_does_not_block_a_late_upload(s3, proof_bucket, artifacts):
    """The real ordering hazard: setup attaches the CDN while the workflow may
    still be uploading. An explicit deny here would lose the proof."""
    statement, bundle = artifacts
    s3mod.create_bucket(s3, proof_bucket, region="us-east-1")

    # setup attaches the distribution before the upload has arrived
    s3mod.put_bucket_policy(
        s3, bucket=proof_bucket,
        policy=json.dumps(
            policies.cloudfront_read_bucket_policy(
                bucket=proof_bucket, distribution_arn="arn:aws:cloudfront::1:distribution/E1"
            )
        ),
    )

    # the workflow's upload still has to succeed
    assert publish_proof.upload(
        s3, bucket=proof_bucket, statement_path=statement, bundle_path=bundle,
        poll_max=60, interval=5,
    ) is True


def test_the_seal_step_recognises_a_matching_bundle(s3, proof_bucket, artifacts):
    statement, bundle = artifacts
    s3mod.create_bucket(s3, proof_bucket, region="us-east-1")
    publish_proof.upload(
        s3, bucket=proof_bucket, statement_path=statement, bundle_path=bundle,
        poll_max=60, interval=5,
    )

    assert proof.statement_matches_bundle(s3, bucket=proof_bucket) is True


def test_the_seal_step_notices_a_bundle_that_attests_something_else(s3, proof_bucket, artifacts):
    statement, _ = artifacts
    s3mod.create_bucket(s3, proof_bucket, region="us-east-1")
    s3mod.put_file(s3, bucket=proof_bucket, key=workflow_config.STATEMENT_FILE, path=statement)
    s3mod.put_json(s3, bucket=proof_bucket, key=workflow_config.BUNDLE_FILE,
                   body=json.dumps({"subject": [{"digest": {"sha256": "0" * 64}}]}).encode())

    assert proof.statement_matches_bundle(s3, bucket=proof_bucket) is False


def test_a_bucket_that_never_appears_leaves_the_run_green(s3, prefix, artifacts):
    """The statement is signed and attached to the run either way; only the
    account's own copy is missing."""
    statement, bundle = artifacts

    published = publish_proof.upload(
        s3, bucket=f"{prefix}never-created-at-all", statement_path=statement,
        bundle_path=bundle, poll_max=0, interval=1, log=lambda *_: None,
    )

    assert published is False
