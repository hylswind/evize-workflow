"""setup/proof.py — waiting for the proof to land, and the sealing that follows.

This runs at the very end of a bring-up, unwatched, and decides whether the
starter user is retired. What the account does not do is inspect the pair it
published: the statement and its bundle are there for an outside verifier, and
an account grading its own proof proves nothing.
"""

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


def publish(s3, *, statement=STATEMENT, bundle=b"{}"):
    """Both objects landing is all this half cares about — their contents are
    for whoever verifies them from outside."""
    s3mod.put_json(s3, bucket=BUCKET, key=config.STATEMENT_KEY, body=statement)
    s3mod.put_json(s3, bucket=BUCKET, key=config.BUNDLE_KEY, body=bundle)


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


def test_the_writer_is_retired_even_when_the_proof_never_arrives(s3, monkeypatch):
    """Nobody is left who could publish it — the starter credentials only ever
    existed in the runner, and a bundle needs a workflow's OIDC token — so
    keeping the user would leave a live access key behind for nothing."""
    monkeypatch.setattr(config, "PROOF_OBJECT_POLL_MAX_SECONDS", 0)
    monkeypatch.setattr(config, "PROOF_OBJECT_POLL_INTERVAL", 0)
    iam = FakeIam()
    said = []

    published = proof.await_and_seal(s3, iam, bucket=BUCKET, res=Resources(), log=said.append)

    assert published is False
    assert iam.deleted == ["enclavize-starter"]
    assert any("no proof arrived" in line for line in said)
