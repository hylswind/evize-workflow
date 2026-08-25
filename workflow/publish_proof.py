"""Upload the signed statement and its bundle to the account's proof bucket.

Runs after the attestation exists, because the bundle only exists then. This is
the one place phase A has to coordinate with the setup program, which is
running in parallel and creates the bucket. Neither can message the other, so
both derive the bucket's name from the account id and this side waits for it to
appear.

Timing out is not a failure. The statement is signed and attached to the run
either way; only the account's own copy is missing, and that is worth a warning
rather than a red build.
"""

import json
import os
import sys

import boto3

from enclavize.aws import s3

from . import config


def load_handover(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def upload(s3_client, *, bucket: str, statement_path, bundle_path,
           poll_max: int, interval: int, log=print) -> bool:
    """Wait for the bucket, then write both objects. False if it never appeared."""
    log(f"waiting for the setup program to create {bucket}")
    if not s3.await_bucket(s3_client, bucket, poll_max=poll_max, interval=interval):
        log(
            f"WARNING: {bucket} did not appear within {poll_max}s. The statement is "
            "signed and attached to this run, but the account has no copy of it. "
            "The setup program will report proof as missing."
        )
        return False
    s3.put_file(s3_client, bucket=bucket, key=config.STATEMENT_FILE, path=statement_path)
    s3.put_file(s3_client, bucket=bucket, key=config.BUNDLE_FILE, path=bundle_path)
    log(f"published {config.STATEMENT_FILE} and {config.BUNDLE_FILE} to {bucket}")
    return True


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    bundle_path = argv[0] if argv else os.environ.get("ENCLAVIZE_BUNDLE_PATH")
    if not bundle_path:
        raise SystemExit("enclavize: the attestation bundle path is required")
    if not os.path.exists(config.HANDOVER_FILE):
        raise SystemExit(f"enclavize: {config.HANDOVER_FILE} is missing; did the sealing run finish?")

    handover = load_handover(config.HANDOVER_FILE)
    session = boto3.Session(
        aws_access_key_id=handover["starterKey"],
        aws_secret_access_key=handover["starterSecret"],
        region_name=handover.get("region", config.REGION),
    )
    upload(
        session.client("s3"),
        bucket=handover["proofBucket"],
        statement_path=config.STATEMENT_FILE,
        bundle_path=bundle_path,
        poll_max=config.PROOF_BUCKET_POLL_MAX_SECONDS,
        interval=config.PROOF_BUCKET_POLL_INTERVAL,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
