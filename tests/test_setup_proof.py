"""setup/proof.py — the check that the published bundle attests the published
statement, and the sealing that follows it.

This runs at the very end of a bring-up, unwatched, and decides whether the
starter user is retired. Getting it wrong either leaves a writer alive forever
or deletes the only identity that could ever publish the proof.
"""

import hashlib
import json

import boto3
import pytest
from constants import ACCOUNT_ID, REGION
from moto import mock_aws

from enclavize.aws import s3 as s3mod
from setup import config, proof

BUCKET = f"enclavize-proof-{ACCOUNT_ID}"
STATEMENT = json.dumps({"accountID": ACCOUNT_ID, "debug": False}).encode()


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name=REGION)
        client.create_bucket(Bucket=BUCKET)
        yield client


def publish(s3, *, statement=STATEMENT, bundle=None):
    if bundle is None:
        digest = hashlib.sha256(statement).hexdigest()
        bundle = json.dumps({"subject": [{"digest": {"sha256": digest}}]}).encode()
    s3mod.put_json(s3, bucket=BUCKET, key=config.STATEMENT_KEY, body=statement)
    s3mod.put_json(s3, bucket=BUCKET, key=config.BUNDLE_KEY, body=bundle)


def test_a_bundle_that_attests_the_statement_is_accepted(s3):
    publish(s3)
    assert proof.statement_matches_bundle(s3, bucket=BUCKET) is True


def test_a_bundle_for_a_different_statement_is_rejected(s3):
    """The pair has to be self-consistent, or proof.{domain} would serve a
    signature that covers something else."""
    publish(s3, bundle=json.dumps({"subject": [{"digest": {"sha256": "0" * 64}}]}).encode())
    assert proof.statement_matches_bundle(s3, bucket=BUCKET) is False


def test_the_digest_is_of_the_exact_bytes_published(s3):
    # Not of a re-serialised copy: the attestation covers the file as written.
    statement = b'{\n  "accountID": "123456789012"\n}\n'
    publish(s3, statement=statement)
    assert proof.statement_matches_bundle(s3, bucket=BUCKET) is True

    # The same JSON with different whitespace is a different subject.
    s3mod.put_json(s3, bucket=BUCKET, key=config.STATEMENT_KEY,
                   body=b'{"accountID":"123456789012"}')
    assert proof.statement_matches_bundle(s3, bucket=BUCKET) is False


def test_an_unreadable_bundle_does_not_crash_the_seal(s3):
    # A bundle is JSON, but the check only looks for a digest in its text.
    publish(s3, bundle=b"\xff\xfe not utf-8 at all")
    assert proof.statement_matches_bundle(s3, bucket=BUCKET) is False


class FakeIam:
    def __init__(self):
        self.deleted = []

    def get_paginator(self, name):
        return self

    def paginate(self, **kwargs):
        return [{"AccessKeyMetadata": [], "PolicyNames": [], "AttachedPolicies": []}]

    def delete_login_profile(self, **kwargs):
        pass

    def delete_user(self, UserName):
        self.deleted.append(UserName)


class Resources:
    starter_user = "enclavize-starter"


def test_the_writer_is_retired_once_the_proof_has_landed(s3):
    """After this nothing in the account can write the proof bucket."""
    publish(s3)
    iam = FakeIam()

    assert proof.await_and_seal(s3, iam, bucket=BUCKET, res=Resources(), log=lambda *_: None)

    assert iam.deleted == ["enclavize-starter"]


def test_the_writer_survives_when_the_proof_never_arrives(s3, monkeypatch):
    """Deleting it would make publishing impossible for good, so a run that
    failed before signing must leave the door open."""
    monkeypatch.setattr(config, "PROOF_OBJECT_POLL_MAX_SECONDS", 0)
    monkeypatch.setattr(config, "PROOF_OBJECT_POLL_INTERVAL", 0)
    iam = FakeIam()

    published = proof.await_and_seal(s3, iam, bucket=BUCKET, res=Resources(), log=lambda *_: None)

    assert published is False
    assert iam.deleted == []


def test_a_mismatched_bundle_is_reported_but_still_seals(s3, monkeypatch):
    """The objects did arrive, so the writer has done its job; the mismatch is
    worth saying out loud rather than leaving a credential alive over."""
    publish(s3, bundle=json.dumps({"subject": [{"digest": {"sha256": "0" * 64}}]}).encode())
    iam = FakeIam()
    said = []

    assert proof.await_and_seal(s3, iam, bucket=BUCKET, res=Resources(), log=said.append)

    assert any("does not attest" in line for line in said)
    assert iam.deleted == ["enclavize-starter"]
