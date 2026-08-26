"""CloudFront in front of a private bucket, via origin access control.

The buckets stay closed to the world; the distribution is the only reader, and
the bucket policy grants that by naming the distribution's ARN.

Distributions are slow: roughly five to fifteen minutes to deploy, and teardown
needs a disable-and-wait first. Tests therefore hand cleanup to a reaper rather
than waiting inline.
"""

import time


# Fixed for every CloudFront distribution; Route 53 alias records need it as the
# target's hosted zone. Confirmed against the SDK's own Route 53 examples.
CLOUDFRONT_HOSTED_ZONE_ID = "Z2FDTNDATAQYW2"

_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def create_origin_access_control(cf, *, name: str, description: str = "") -> str:
    """Create one. The name must not already be taken.

    Callers name these per run rather than per bucket, so a collision here is
    not a bring-up meeting its own leftovers — it is a name this run does not
    own. Adopting it would mean trusting a configuration nobody checked: an
    access control saying `never` sign leaves CloudFront unable to read the
    bucket at all.
    """
    return cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": name,
            "Description": description,
            "SigningProtocol": "sigv4",
            "SigningBehavior": "always",
            "OriginAccessControlOriginType": "s3",
        }
    )["OriginAccessControl"]["Id"]


def delete_origin_access_control(cf, oac_id: str) -> None:
    """Needs the current ETag as IfMatch, which only a read supplies."""
    etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)


def create_distribution(
    cf,
    *,
    caller_reference: str,
    bucket: str,
    region: str,
    aliases,
    certificate_arn: str,
    oac_id: str,
    default_root_object: str = "index.html",
    comment: str = "",
) -> dict:
    """A distribution serving one private bucket over HTTPS.

    Returns id, ARN and domain name — the ARN is what the bucket policy has to
    name, so it is needed before the bucket can be opened to the distribution.
    """
    origin_id = f"s3-{bucket}"
    config = {
        "CallerReference": caller_reference,
        "Comment": comment,
        "Enabled": True,
        "DefaultRootObject": default_root_object,
        "Aliases": {"Quantity": len(aliases), "Items": list(aliases)},
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    # The regional endpoint, so requests do not depend on the
                    # global bucket redirect.
                    "DomainName": f"{bucket}.s3.{region}.amazonaws.com",
                    "OriginAccessControlId": oac_id,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "redirect-to-https",
            "AllowedMethods": {
                "Quantity": 2,
                "Items": ["GET", "HEAD"],
                "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
            },
            "Compress": True,
            "CachePolicyId": _CACHING_OPTIMIZED_POLICY_ID,
        },
        "ViewerCertificate": {
            "ACMCertificateArn": certificate_arn,
            "SSLSupportMethod": "sni-only",
            "MinimumProtocolVersion": "TLSv1.2_2021",
        },
    }
    distribution = cf.create_distribution(DistributionConfig=config)["Distribution"]
    return {
        "id": distribution["Id"],
        "arn": distribution["ARN"],
        "domain_name": distribution["DomainName"],
    }


def await_deployed(cf, distribution_id: str, *, poll_max: int, interval: int,
                   sleep=time.sleep, now=time.monotonic) -> bool:
    """Wait for Deployed. False on timeout.

    Until this returns the alias resolves to nothing useful, which matters
    because the operator's only sign of life is the dashboard responding.
    """
    deadline = now() + poll_max
    while True:
        status = cf.get_distribution(Id=distribution_id)["Distribution"]["Status"]
        if status == "Deployed":
            return True
        if now() >= deadline:
            return False
        sleep(interval)


def disable(cf, distribution_id: str) -> None:
    """Switch a distribution off, the required first step before deleting it."""
    current = cf.get_distribution(Id=distribution_id)
    config = current["Distribution"]["DistributionConfig"]
    if not config["Enabled"]:
        return
    config["Enabled"] = False
    cf.update_distribution(Id=distribution_id, DistributionConfig=config, IfMatch=current["ETag"])


def delete(cf, distribution_id: str) -> None:
    """Delete a distribution that is already disabled and redeployed."""
    etag = cf.get_distribution(Id=distribution_id)["ETag"]
    cf.delete_distribution(Id=distribution_id, IfMatch=etag)
