"""Buckets and objects, including the wait at the heart of the proof handover.

The workflow and the setup program run in parallel with no channel between
them: setup creates the proof bucket first thing, and the workflow waits for it
to appear before uploading what it signed.
"""

import time

from botocore.exceptions import ClientError

# HeadBucket answers 404 when the bucket is absent and 403 when it exists but
# belongs to someone else — a distinction that decides whether waiting can ever
# succeed.
_ABSENT_CODES = {"404", "NoSuchBucket", "NotFound"}
_FORBIDDEN_CODES = {"403", "AccessDenied", "Forbidden"}


def _error_code(exc: ClientError) -> str:
    error = exc.response.get("Error", {})
    return str(error.get("Code", ""))


def create_bucket(s3, bucket: str, *, region: str) -> None:
    """Create a private, versioned bucket.

    us-east-1 is the one region that rejects a LocationConstraint, so the
    argument is omitted there rather than passed as "us-east-1".
    """
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        # Re-running against an account that already has the bucket is normal.
        if _error_code(exc) not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    # Versioning keeps superseded proof retrievable; combined with a writer that
    # has PutObject but no delete, what lands here cannot be quietly rewritten.
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})


def bucket_exists(s3, bucket: str) -> bool:
    """True if it exists and we may see it.

    Raises on 403: the name is taken by another account, so no amount of waiting
    will help and the caller should fail rather than spin.
    """
    try:
        s3.head_bucket(Bucket=bucket)
        return True
    except ClientError as exc:
        code = _error_code(exc)
        if code in _ABSENT_CODES:
            return False
        if code in _FORBIDDEN_CODES:
            raise RuntimeError(
                f"enclavize: bucket {bucket!r} exists but is not ours (HTTP 403); "
                "the name is taken by another account"
            ) from None
        raise


def await_bucket(s3, bucket: str, *, poll_max: int, interval: int, sleep=time.sleep, now=time.monotonic) -> bool:
    """Wait for another process to create the bucket. False on timeout.

    Timing out is a degraded outcome, not a failure: the statement is already
    signed and attached to the run, so the caller warns and carries on.
    """
    deadline = now() + poll_max
    while True:
        if bucket_exists(s3, bucket):
            return True
        if now() >= deadline:
            return False
        sleep(interval)


def put_json(s3, *, bucket: str, key: str, body: bytes, content_type: str = "application/json") -> None:
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type)


def put_file(s3, *, bucket: str, key: str, path, content_type: str = "application/json") -> None:
    with open(path, "rb") as handle:
        put_json(s3, bucket=bucket, key=key, body=handle.read(), content_type=content_type)


def object_exists(s3, *, bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as exc:
        if _error_code(exc) in _ABSENT_CODES | {"NoSuchKey"}:
            return False
        raise


def await_objects(
    s3, *, bucket: str, keys, poll_max: int, interval: int, sleep=time.sleep, now=time.monotonic
) -> bool:
    """Wait until every key is present. False on timeout."""
    deadline = now() + poll_max
    while True:
        if all(object_exists(s3, bucket=bucket, key=key) for key in keys):
            return True
        if now() >= deadline:
            return False
        sleep(interval)


def get_bytes(s3, *, bucket: str, key: str) -> bytes:
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def put_bucket_policy(s3, *, bucket: str, policy: str) -> None:
    s3.put_bucket_policy(Bucket=bucket, Policy=policy)


def delete_bucket(s3, bucket: str) -> None:
    """Empty a versioned bucket and remove it. Used by tests and the reaper."""
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        stale = [
            {"Key": item["Key"], "VersionId": item["VersionId"]}
            for field in ("Versions", "DeleteMarkers")
            for item in page.get(field, [])
        ]
        if stale:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": stale})
    s3.delete_bucket(Bucket=bucket)
