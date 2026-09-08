"""The account's own copy of the proof that it is sealed.

This is where the two halves of enclavize meet. The workflow is running in
parallel and cannot be talked to; it is waiting for this bucket to exist, and
will upload the signed statement into it as soon as it does. Both sides derive
the bucket's name from the account id, so no channel is needed.

Three consequences shape the code below:
- the bucket is created before anything slow, or the workflow waits on DNS
- the bucket policy is allow-only, or it would deny an upload still in flight
- the wait for the objects outlasts the workflow's own wait for the bucket by a
  wide margin, so reaching the end of it means there is no upload still coming
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
    """Wait for the proof to arrive, then retire the writer either way.

    Returns whether the proof landed, which is all the dashboard needs to say.

    The writer goes even when it did not. Waiting an hour and finding nothing
    means the workflow died, and a dead run does not come back: the starter
    credentials only ever existed inside the runner, and a bundle can only be
    signed by a workflow holding an OIDC token. Nobody is left who could publish,
    so keeping the user leaves a live access key in an account whose whole claim
    is that no human credential remains.
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
        log("WARNING: no proof arrived; the dashboard will report proof as missing.")

    # The pair is not inspected here. It is published for whoever wants to check
    # it, and a statement its bundle does not attest means this account was not
    # sealed — which is exactly what an outside verifier is for. An account
    # grading its own proof proves nothing.
    #
    # Nothing in the account can write here afterwards: the apply boundary
    # denies the bucket outright, and no principal can assume the admin role.
    iam.delete_user(iam_client, user=res.starter_user)
    log(f"deleted {res.starter_user}; the proof can no longer be rewritten from inside")
    return landed
