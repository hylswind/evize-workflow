"""The dashboard: the only window into a sealed account.

Nothing else reports progress. The operator watches for dashboard.{domain} to
start answering, which is why it is built before the apply machinery — its
being reachable at all proves DNS, the certificate and the CDN are working.

The page itself lives in assets/dashboard as ordinary static files and is
uploaded verbatim: no build step, no framework, nothing generated. What changes
during a bring-up is status.json, which the page reads from the same bucket.
"""

import json
import mimetypes
import pathlib

from enclavize.aws import cdn, dns, s3
from enclavize.logic import policies

from . import config

ASSETS = pathlib.Path(__file__).parent / "assets" / "dashboard"

# Guessing is fine for the common cases, but S3 serves whatever it is told and a
# wrong type on the stylesheet or the script would break the page silently.
_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


def content_type_for(path) -> str:
    suffix = pathlib.Path(path).suffix.lower()
    if suffix in _TYPES:
        return _TYPES[suffix]
    guessed, _ = mimetypes.guess_type(str(path))
    return guessed or "application/octet-stream"


def asset_files(root=ASSETS) -> list:
    """Every file in the static folder, as (key, path) pairs.

    Keys keep the folder's own layout, so a nested asset lands where the page
    expects it.
    """
    root = pathlib.Path(root)
    return sorted(
        (path.relative_to(root).as_posix(), path)
        for path in root.rglob("*")
        if path.is_file()
    )


def upload_assets(s3_client, *, bucket: str, root=ASSETS) -> list:
    """Copy the static folder into the bucket as it stands."""
    uploaded = []
    for key, path in asset_files(root):
        s3.put_json(
            s3_client,
            bucket=bucket,
            key=key,
            body=path.read_bytes(),
            content_type=content_type_for(path),
        )
        uploaded.append(key)
    return uploaded


def render_status(*, domain: str, state: str, proof: str = "pending") -> bytes:
    """The one file that changes during a bring-up.

    Machine-readable so the operator can poll it directly, and read by the page
    so a browser shows the same thing.
    """
    return (json.dumps({"domain": domain, "state": state, "proof": proof}, indent=2) + "\n").encode()


def create_bucket(s3_client, *, bucket: str, region: str, domain: str) -> str:
    """Create the bucket and fill it. Seconds, and needs no certificate.

    Deliberately separate from attach_cdn: the content is ready long before
    anything can serve it, and bundling the two would put a folder copy behind
    the half-hour certificate wait for no reason.
    """
    s3.create_bucket(s3_client, bucket, region=region)
    upload_assets(s3_client, bucket=bucket)
    mark(s3_client, bucket=bucket, domain=domain, state="starting")
    return bucket


def attach_cdn(cf_client, s3_client, r53_client, *, bucket: str, host: str, zone_id: str,
               certificate_arn: str, caller_reference: str, region: str) -> dict:
    """Put the finished bucket behind HTTPS at dashboard.{domain}.

    Returns without waiting for the distribution to deploy, so this one and the
    proof site can spend their ten-odd minutes concurrently rather than in turn.
    """
    # Named for this run, not for the bucket: an access control outlives the
    # distribution that used it, and a name shared across runs is a name this
    # one would have to adopt without knowing how it was configured.
    oac_id = cdn.create_origin_access_control(
        cf_client, name=f"{caller_reference}-oac", description="enclavize dashboard"
    )
    distribution = cdn.create_distribution(
        cf_client,
        caller_reference=caller_reference,
        bucket=bucket,
        region=region,
        aliases=[host],
        certificate_arn=certificate_arn,
        oac_id=oac_id,
        default_root_object=config.INDEX_KEY,
        comment="enclavize dashboard",
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
        comment="enclavize dashboard alias",
    )
    return distribution


def mark(s3_client, *, bucket: str, domain: str, state: str, proof: str = "pending") -> None:
    s3.put_json(
        s3_client,
        bucket=bucket,
        key=config.STATUS_KEY,
        body=render_status(domain=domain, state=state, proof=proof),
    )
