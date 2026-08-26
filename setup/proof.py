"""The account's own copy of the proof that it is sealed.

This is where the two halves of enclavize meet. The workflow is running in
parallel and cannot be talked to; it is waiting for this bucket to exist, and
will upload the signed statement into it as soon as it does. Both sides derive
the bucket's name from the account id, so no channel is needed.

Three consequences shape the code below:
- the bucket is created before anything slow, or the workflow waits on DNS
- the bucket policy is allow-only, or it would deny an upload still in flight
- the starter user is deleted only after the objects have landed, because
  deleting it early would make the proof impossible to publish, ever
"""

import json

from enclavize.aws import cdn, dns, iam, s3
from enclavize.logic import naming, policies

from . import config


def create_bucket(s3_client, *, account_id: str, region: str) -> str:
    """Create the proof bucket. The first thing the bring-up does.

    The workflow is already waiting on this; anything slow scheduled ahead of it
    is time the workflow spends polling.
    """
    bucket = naming.proof_bucket_name(account_id)
    s3.create_bucket(s3_client, bucket, region=region)
    return bucket


def attach_cdn(cf_client, s3_client, r53_client, *, bucket: str, host: str, zone_id: str,
               certificate_arn: str, caller_reference: str, region: str) -> dict:
    """Put the proof bucket behind HTTPS at proof.{domain}.

    The bucket policy grants read to this distribution and denies nothing: an
    explicit deny would race the workflow's upload, which may still be in
    flight. Immutability comes from retiring the writer, not from this policy.
    """
    oac_id = cdn.create_origin_access_control(
        cf_client, name=f"{caller_reference}-oac", description="enclavize proof"
    )
    distribution = cdn.create_distribution(
        cf_client,
        caller_reference=caller_reference,
        bucket=bucket,
        region=region,
        aliases=[host],
        certificate_arn=certificate_arn,
        oac_id=oac_id,
        default_root_object=config.STATEMENT_KEY,
        comment="enclavize proof",
    )
    s3.put_bucket_policy(
        s3_client,
        bucket=bucket,
        policy=json.dumps(
            policies.cloudfront_read_bucket_policy(bucket=bucket, distribution_arn=distribution["arn"])
        ),
    )
    dns.change_records(
        r53_client,
        zone_id=zone_id,
        changes=[
            dns.upsert_alias(host, target_dns=distribution["domain_name"],
                             hosted_zone_id=cdn.CLOUDFRONT_HOSTED_ZONE_ID, record_type=record_type)
            for record_type in ("A", "AAAA")
        ],
        comment="enclavize proof alias",
    )
    return distribution


def await_and_seal(s3_client, iam_client, *, bucket: str, res, log=print) -> bool:
    """Wait for the proof to arrive, check it, then retire the writer.

    Returns whether the proof landed. If it never does — which means the
    workflow failed around signing — the starter user is deliberately left
    alive, because deleting it would make publishing impossible for good.
    """
    keys = [config.STATEMENT_KEY, config.BUNDLE_KEY]
    log(f"waiting for the workflow to publish {', '.join(keys)}")
    landed = s3.await_objects(
        s3_client,
        bucket=bucket,
        keys=keys,
        poll_max=config.PROOF_OBJECT_POLL_MAX_SECONDS,
        interval=config.PROOF_OBJECT_POLL_INTERVAL,
    )
    if not landed:
        log(
            "WARNING: no proof arrived. Keeping the starter user so it can still "
            "be published; the dashboard will report proof as missing."
        )
        return False

    if not statement_matches_bundle(s3_client, bucket=bucket):
        log("WARNING: the published bundle does not attest the published statement")

    # Nothing in the account can write here afterwards: the apply boundary
    # denies the bucket outright, and no principal can assume the admin role.
    iam.delete_user(iam_client, user=res.starter_user)
    log(f"deleted {res.starter_user}; the proof can no longer be rewritten from inside")
    return True


def statement_matches_bundle(s3_client, *, bucket: str) -> bool:
    """Check the bundle really attests the statement sitting beside it."""
    import hashlib

    statement = s3.get_bytes(s3_client, bucket=bucket, key=config.STATEMENT_KEY)
    digest = hashlib.sha256(statement).hexdigest()
    bundle = s3.get_bytes(s3_client, bucket=bucket, key=config.BUNDLE_KEY).decode("utf-8", "replace")
    return digest in bundle
