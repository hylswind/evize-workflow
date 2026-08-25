"""Publishing proof into the account — the one place the two parallel phases meet.

The bucket is created by the setup program, which this side cannot talk to. The
coordination is a derived name plus a wait, and the degraded path matters as
much as the happy one: a run that cannot publish must still be a green run with
a signed statement.
"""

import json

import boto3
import pytest
from botocore.exceptions import ClientError
from constants import ACCOUNT_ID, REGION
from moto import mock_aws

from enclavize.logic import naming
from workflow import config, publish_proof

BUCKET = naming.proof_bucket_name(ACCOUNT_ID)


@pytest.fixture
def s3():
    with mock_aws():
        yield boto3.client("s3", region_name=REGION)


@pytest.fixture
def artifacts(tmp_path):
    statement = tmp_path / config.STATEMENT_FILE
    bundle = tmp_path / config.BUNDLE_FILE
    statement.write_text('{"accountID":"123456789012"}', encoding="utf-8")
    bundle.write_text('{"dsseEnvelope":{}}', encoding="utf-8")
    return statement, bundle


def publish(s3, artifacts, **overrides):
    statement, bundle = artifacts
    kwargs = dict(
        bucket=BUCKET,
        statement_path=statement,
        bundle_path=bundle,
        poll_max=900,
        interval=15,
        log=lambda *_: None,
    )
    kwargs.update(overrides)
    return publish_proof.upload(s3, **kwargs)


def test_both_objects_land_when_the_bucket_is_ready(s3, artifacts):
    s3.create_bucket(Bucket=BUCKET)

    assert publish(s3, artifacts) is True

    keys = {o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET)["Contents"]}
    assert keys == {config.STATEMENT_FILE, config.BUNDLE_FILE}


def test_what_is_uploaded_is_byte_for_byte_what_was_signed(s3, artifacts):
    s3.create_bucket(Bucket=BUCKET)
    statement, bundle = artifacts

    publish(s3, artifacts)

    stored = s3.get_object(Bucket=BUCKET, Key=config.STATEMENT_FILE)["Body"].read()
    assert stored == statement.read_bytes()
    stored_bundle = s3.get_object(Bucket=BUCKET, Key=config.BUNDLE_FILE)["Body"].read()
    assert stored_bundle == bundle.read_bytes()


def test_a_bucket_that_never_appears_is_a_warning_not_a_failure(s3, artifacts):
    """The statement is signed and attached to the run either way."""
    messages = []

    assert publish(s3, artifacts, poll_max=0, interval=1, log=messages.append) is False

    assert any("WARNING" in message for message in messages)
    assert any("signed and attached" in message for message in messages)


def test_it_waits_rather_than_giving_up_on_the_first_look(artifacts):
    # The setup program creates the bucket as its first action, but the instance
    # still has to boot first.
    class Appearing:
        def __init__(self):
            self.looks = 0
            self.uploaded = []

        def head_bucket(self, **_):
            self.looks += 1
            if self.looks < 3:
                raise ClientError({"Error": {"Code": "404", "Message": "x"}}, "HeadBucket")
            return {}

        def put_object(self, **kwargs):
            self.uploaded.append(kwargs["Key"])

    client = Appearing()
    import enclavize.aws.s3 as s3mod

    original = s3mod.await_bucket
    try:
        # Drive the module's own wait, but without real sleeping.
        s3mod.await_bucket = lambda c, b, *, poll_max, interval: original(
            c, b, poll_max=poll_max, interval=interval, sleep=lambda *_: None, now=lambda: 0
        )
        assert publish(client, artifacts) is True
    finally:
        s3mod.await_bucket = original

    assert client.looks == 3
    assert set(client.uploaded) == {config.STATEMENT_FILE, config.BUNDLE_FILE}


def test_a_bucket_owned_by_someone_else_fails_instead_of_waiting(artifacts):
    # The name is taken by another account, so waiting can never succeed.
    class Taken:
        def head_bucket(self, **_):
            raise ClientError({"Error": {"Code": "403", "Message": "x"}}, "HeadBucket")

    with pytest.raises(RuntimeError, match="not ours"):
        publish(Taken(), artifacts)


def test_the_handover_file_is_read_back(tmp_path):
    path = tmp_path / "handover.json"
    path.write_text(
        json.dumps(
            {
                "proofBucket": BUCKET,
                "starterKey": "AKIA",
                "starterSecret": "s",
                "region": REGION,
            }
        ),
        encoding="utf-8",
    )
    assert publish_proof.load_handover(path)["proofBucket"] == BUCKET


def test_publishing_without_a_bundle_path_is_refused():
    with pytest.raises(SystemExit, match="bundle path is required"):
        publish_proof.main([])
