"""The bucket waiting that carries the proof handover between two parallel phases."""

import boto3
import pytest
from botocore.exceptions import ClientError
from constants import REGION, clock, no_sleep
from moto import mock_aws

from enclavize.aws import s3 as s3mod

BUCKET = "enclavize-proof-123456789012"


@pytest.fixture
def s3():
    with mock_aws():
        yield boto3.client("s3", region_name=REGION)


class FakeS3:
    """Stands in where a specific error code has to be provoked."""

    def __init__(self, code):
        self.code = code
        self.calls = 0

    def head_bucket(self, **_kwargs):
        self.calls += 1
        raise ClientError({"Error": {"Code": self.code, "Message": "x"}}, "HeadBucket")


def test_create_makes_a_private_versioned_bucket(s3):
    s3mod.create_bucket(s3, BUCKET, region=REGION)
    assert s3mod.bucket_exists(s3, BUCKET)
    versioning = s3.get_bucket_versioning(Bucket=BUCKET)
    assert versioning["Status"] == "Enabled"
    block = s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"]
    assert block["BlockPublicAcls"] is True
    # The bucket policy must stay usable: CloudFront reads through one.
    assert block["BlockPublicPolicy"] is False


def test_create_is_idempotent(s3):
    s3mod.create_bucket(s3, BUCKET, region=REGION)
    s3mod.create_bucket(s3, BUCKET, region=REGION)
    assert s3mod.bucket_exists(s3, BUCKET)


def test_us_east_1_gets_no_location_constraint():
    """The one region that rejects CreateBucketConfiguration."""
    seen = {}

    class Recorder:
        def create_bucket(self, **kwargs):
            seen.update(kwargs)

        def put_public_access_block(self, **_):
            pass

        def put_bucket_versioning(self, **_):
            pass

    s3mod.create_bucket(Recorder(), BUCKET, region="us-east-1")
    assert "CreateBucketConfiguration" not in seen

    seen.clear()
    s3mod.create_bucket(Recorder(), BUCKET, region="eu-west-1")
    assert seen["CreateBucketConfiguration"] == {"LocationConstraint": "eu-west-1"}


def test_a_missing_bucket_is_not_an_error(s3):
    assert s3mod.bucket_exists(s3, "definitely-not-created") is False


def test_a_bucket_owned_by_someone_else_stops_the_wait():
    # 403 means the name is taken by another account: waiting can never succeed,
    # so it must fail loudly rather than spin until timeout.
    fake = FakeS3("403")
    with pytest.raises(RuntimeError, match="not ours"):
        s3mod.bucket_exists(fake, BUCKET)


def test_await_returns_as_soon_as_the_bucket_appears(s3):
    s3mod.create_bucket(s3, BUCKET, region=REGION)
    assert s3mod.await_bucket(s3, BUCKET, poll_max=900, interval=15, sleep=no_sleep, now=clock([0, 1]))


def test_await_gives_up_without_raising(s3):
    # A timeout is degraded, not fatal: the statement is signed either way.
    assert s3mod.await_bucket(
        s3, "never-created", poll_max=900, interval=15, sleep=no_sleep, now=clock([0, 1000])
    ) is False


def test_await_keeps_polling_until_the_deadline():
    calls = {"n": 0}

    class Appearing:
        def head_bucket(self, **_kwargs):
            calls["n"] += 1
            if calls["n"] < 3:
                raise ClientError({"Error": {"Code": "404", "Message": "x"}}, "HeadBucket")
            return {}

    assert s3mod.await_bucket(
        Appearing(), BUCKET, poll_max=900, interval=15, sleep=no_sleep, now=clock([0, 1, 2, 3])
    )
    assert calls["n"] == 3


def test_put_and_read_back_a_file(s3, tmp_path):
    s3mod.create_bucket(s3, BUCKET, region=REGION)
    path = tmp_path / "statement.json"
    path.write_text('{"ok":true}', encoding="utf-8")

    s3mod.put_file(s3, bucket=BUCKET, key="statement.json", path=path)

    assert s3mod.get_bytes(s3, bucket=BUCKET, key="statement.json") == b'{"ok":true}'
    stored = s3.head_object(Bucket=BUCKET, Key="statement.json")
    assert stored["ContentType"] == "application/json"


def test_await_objects_waits_for_every_key(s3):
    s3mod.create_bucket(s3, BUCKET, region=REGION)
    s3mod.put_json(s3, bucket=BUCKET, key="statement.json", body=b"{}")

    # Only one of the two is present, so this must not report success.
    assert s3mod.await_objects(
        s3,
        bucket=BUCKET,
        keys=["statement.json", "bundle.jsonl"],
        poll_max=60,
        interval=5,
        sleep=no_sleep,
        now=clock([0, 100]),
    ) is False

    s3mod.put_json(s3, bucket=BUCKET, key="bundle.jsonl", body=b"{}")
    assert s3mod.await_objects(
        s3,
        bucket=BUCKET,
        keys=["statement.json", "bundle.jsonl"],
        poll_max=60,
        interval=5,
        sleep=no_sleep,
        now=clock([0, 1]),
    )


def test_delete_empties_a_versioned_bucket_first(s3):
    s3mod.create_bucket(s3, BUCKET, region=REGION)
    s3mod.put_json(s3, bucket=BUCKET, key="a.json", body=b"1")
    s3mod.put_json(s3, bucket=BUCKET, key="a.json", body=b"2")  # a second version

    s3mod.delete_bucket(s3, BUCKET)

    assert s3mod.bucket_exists(s3, BUCKET) is False
