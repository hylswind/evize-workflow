"""Phase B: bring the sealed account up.

Runs on the instance the workflow launched, under the admin role, once the go
flag has been fired. Nobody can see this happen — the console is closed and
there are no credentials — so the ordering is chosen around two things:

- the proof bucket is created first, because the workflow is already waiting on
  it and everything after it is slow
- the dashboard is built before the apply machinery, because it answering at
  all is the operator's only sign that the bring-up is working

The instance destroys itself at the end. Nothing is left holding admin.
"""

import datetime
import os
import sys
import urllib.request
import uuid

from enclavize.aws import acm, cdn, dns, domains, ec2, s3, sts
from enclavize.logic import naming

from . import apply, clients, config, dashboard, proof

AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
APPLY_INSTANCE_TYPE = "t3.small"


def env(name: str, *, required: bool = True) -> str:
    value = os.environ.get(name, "")
    if required and not value:
        raise SystemExit(f"enclavize: {name} is required")
    return value


def instance_id() -> str:
    """This instance's own id, for the last act."""
    token = urllib.request.urlopen(
        urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        ),
        timeout=5,
    ).read().decode()
    return urllib.request.urlopen(
        urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/instance-id",
            headers={"X-aws-ec2-metadata-token": token},
        ),
        timeout=5,
    ).read().decode()


def run(*, domain: str, app_repo: str, api_key: str, region: str, res=None, log=print) -> dict:
    res = res or config.RESOURCES
    session = clients.session(region)
    s3_client = session.client("s3")
    r53 = session.client("route53")
    r53d = session.client("route53domains")
    acm_client = session.client("acm")
    cf = session.client("cloudfront")
    iam_client = session.client("iam")

    account_id = sts.account_id(session.client("sts"))
    reference = naming.caller_reference(account_id, str(uuid.uuid4()))
    log(f"bringing up {domain} in {account_id}")

    dashboard_host = naming.dashboard_host(domain)
    proof_host = naming.proof_host(domain)
    apply_host = naming.apply_host(domain)
    dashboard_bucket = naming.dashboard_bucket_name(account_id)

    # --- everything that needs no waiting, first ---------------------------
    #
    # The certificate is the only thing gating visibility, so nothing cheap
    # should sit behind it.

    # The workflow is blocked polling for this one.
    proof_bucket = proof.create_bucket(s3_client, account_id=account_id, region=region)
    log(f"created {proof_bucket}; the workflow can publish as soon as it has signed")

    # Static files, so this is a folder copy rather than anything built.
    dashboard.create_bucket(s3_client, bucket=dashboard_bucket, region=region, domain=domain)
    log(f"{dashboard_bucket} filled and waiting for a certificate")

    # A transferred domain arrives without its hosted zone.
    zone_id, nameservers = dns.create_hosted_zone(
        r53, domain=domain, caller_reference=reference, comment="enclavize"
    )
    log(f"hosted zone {zone_id}")

    # Kill the mailbox: no mail means no password reset, which closes the last
    # human route back in. It takes effect when the delegation below lands, so
    # there is nothing to wait for here.
    dns.change_records(
        r53, zone_id=zone_id, changes=[dns.null_mx_change(domain)], comment="enclavize null MX"
    )
    log("null MX published; the account's email address dies with the delegation")

    # Requested before the delegation on purpose. The request needs nothing;
    # only validation needs the delegation, and ACM re-checks periodically — so
    # publishing the records now means it can pass the moment delegation lands.
    certificate_arn = acm.request_certificate(
        acm_client, domain=dashboard_host, alternative_names=[proof_host, apply_host],
        idempotency_token=uuid.uuid4().hex[:32],
    )
    records = acm.validation_records(acm_client, certificate_arn)
    dns.change_records(
        r53, zone_id=zone_id,
        changes=[dns.upsert(r["Name"], r["Type"], [r["Value"]]) for r in records],
        comment="enclavize certificate validation",
    )
    log("certificate requested and validation records published")

    # --- hand the domain over, then work while the certificate validates ----

    domains.update_nameservers_and_wait(
        r53d, domain=domain, nameservers=nameservers,
        poll_max=config.NS_OPERATION_POLL_MAX_SECONDS, interval=config.NS_OPERATION_POLL_INTERVAL,
    )
    log("registrar now points at this account's nameservers")

    # None of this needs the certificate — only the account and the bucket
    # names — so it fills the wait instead of following it.
    roles = apply.create_roles(
        iam_client, res=res, account_id=account_id, region=region,
        proof_bucket=proof_bucket, dashboard_bucket=dashboard_bucket,
        domain=domain, hosted_zone_id=zone_id,
    )
    state_machine_arn = apply.create_state_machine(
        session.client("stepfunctions"), session.client("ec2"), session.client("ssm"),
        res=res, app_repo=app_repo, region=region, domain=domain,
        dashboard_bucket=dashboard_bucket, role_arn=roles["sfn_role_arn"],
        ami_param=AMI_PARAM, instance_type=APPLY_INSTANCE_TYPE,
    )
    _, api_id = apply.create_api(
        session.client("apigateway"), iam_client, res=res, region=region, api_key=api_key,
        state_machine_arn=state_machine_arn, api_role_arn=roles["api_role_arn"], account_id=account_id,
    )
    dashboard.mark(s3_client, bucket=dashboard_bucket, domain=domain, state="apply-ready")

    log("waiting for the certificate; this is the longest wait in the bring-up")
    acm.await_issued(acm_client, certificate_arn,
                     poll_max=config.CERT_VALIDATION_POLL_MAX_SECONDS,
                     interval=config.CERT_VALIDATION_POLL_INTERVAL)
    log("certificate issued")

    # --- everything the certificate was blocking ---------------------------

    # Regional, so there is no distribution to propagate and this is immediate.
    url = apply.attach_custom_domain(
        session.client("apigateway"), r53, api_id=api_id, domain=domain,
        certificate_arn=certificate_arn, zone_id=zone_id, region=region,
    )
    log(f"apply endpoint at {url}")

    distributions = {
        "dashboard": dashboard.attach_cdn(
            cf, s3_client, r53, bucket=dashboard_bucket, host=dashboard_host, zone_id=zone_id,
            certificate_arn=certificate_arn, caller_reference=f"{reference}-dashboard", region=region,
        ),
        "proof": proof.attach_cdn(
            cf, s3_client, r53, bucket=proof_bucket, host=proof_host, zone_id=zone_id,
            certificate_arn=certificate_arn, caller_reference=f"{reference}-proof", region=region,
        ),
    }
    # Created together, then waited on together: serially this would cost each
    # distribution's ten-odd minutes one after the other.
    for name, distribution in distributions.items():
        if not cdn.await_deployed(cf, distribution["id"],
                                  poll_max=config.DISTRIBUTION_POLL_MAX_SECONDS,
                                  interval=config.DISTRIBUTION_POLL_INTERVAL):
            log(f"WARNING: the {name} distribution has not finished deploying")
    log(f"https://{dashboard_host} and https://{proof_host} are live")

    # Now that the API and both distributions exist, replace the service-wide
    # denial with one naming only the enclave's own resources — so an
    # application can use API Gateway, Step Functions and CloudFront for itself.
    apply.tighten_boundary(
        iam_client, res=res, account_id=account_id, region=region,
        proof_bucket=proof_bucket, dashboard_bucket=dashboard_bucket,
        domain=domain, hosted_zone_id=zone_id,
        protected={
            "api_id": api_id,
            "distribution_ids": [d["id"] for d in distributions.values()],
        },
    )
    log("boundary narrowed to the enclave's own resources")

    published = proof.await_and_seal(s3_client, iam_client, bucket=proof_bucket, res=res, log=log)

    dashboard.mark(s3_client, bucket=dashboard_bucket, domain=domain, state="complete",
                   proof="published" if published else "missing")
    log("bring-up complete")
    return {
        "account_id": account_id,
        "apply_url": url,
        "proof_published": published,
        "dashboard_bucket": dashboard_bucket,
    }


def main(argv=None):
    region = os.environ.get("ENCLAVIZE_REGION", config.REGION)
    try:
        run(
            domain=env("ENCLAVIZE_DOMAIN"),
            app_repo=env("ENCLAVIZE_APP_REPO"),
            api_key=env("ENCLAVIZE_APPLY_API_KEY"),
            region=region,
        )
    finally:
        # Whatever happened, nothing should be left holding administrator
        # credentials. A failed bring-up is recovered by re-running the
        # workflow, not by logging into this box — there is no way in.
        try:
            ec2.terminate(clients.session(region).client("ec2"), instance_id())
        except Exception as exc:  # noqa: BLE001 - never let cleanup mask the real error
            print(f"WARNING: could not self-terminate: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
