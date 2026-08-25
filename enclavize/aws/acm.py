"""Certificates for the two public hosts.

CloudFront only accepts certificates from us-east-1, which is one of the reasons
enclavize is single-region throughout.

Validation is the longest wait in the whole bring-up: the certificate cannot
issue until the registrar's new delegation has propagated far enough for the
validation records to be visible from outside.
"""

import time


def request_certificate(acm, *, domain: str, alternative_names, idempotency_token: str) -> str:
    """Request a DNS-validated certificate covering every host in one go."""
    return acm.request_certificate(
        DomainName=domain,
        ValidationMethod="DNS",
        SubjectAlternativeNames=list(alternative_names),
        IdempotencyToken=idempotency_token,
    )["CertificateArn"]


def validation_records(acm, certificate_arn: str, *, poll_max: int = 120, interval: int = 5,
                       sleep=time.sleep, now=time.monotonic) -> list:
    """The CNAMEs that prove domain control.

    They do not appear the instant the certificate is requested, so this waits
    for them rather than reading once and finding nothing.
    """
    deadline = now() + poll_max
    while True:
        detail = acm.describe_certificate(CertificateArn=certificate_arn)["Certificate"]
        options = detail.get("DomainValidationOptions", [])
        ready = [opt for opt in options if opt.get("ResourceRecord")]
        # One record per distinct name; duplicates collapse when a SAN validates
        # through the same record.
        if ready and len(ready) == len(options):
            seen, records = set(), []
            for option in ready:
                record = option["ResourceRecord"]
                key = (record["Name"], record["Value"])
                if key not in seen:
                    seen.add(key)
                    records.append(record)
            return records
        if now() >= deadline:
            raise TimeoutError(
                f"enclavize: certificate {certificate_arn} produced no validation records in {poll_max}s"
            )
        sleep(interval)


def await_issued(acm, certificate_arn: str, *, poll_max: int, interval: int,
                 sleep=time.sleep, now=time.monotonic) -> None:
    """Wait for ISSUED. Raises on failure or timeout.

    A certificate stuck in PENDING_VALIDATION almost always means the registrar
    delegation has not propagated yet, so the error says so.
    """
    deadline = now() + poll_max
    while True:
        detail = acm.describe_certificate(CertificateArn=certificate_arn)["Certificate"]
        status = detail.get("Status")
        if status == "ISSUED":
            return
        if status in ("VALIDATION_TIMED_OUT", "FAILED", "REVOKED"):
            reason = detail.get("FailureReason", "no reason given")
            raise RuntimeError(f"enclavize: certificate {certificate_arn} ended {status}: {reason}")
        if now() >= deadline:
            raise TimeoutError(
                f"enclavize: certificate {certificate_arn} still {status} after {poll_max}s; "
                "the registrar's nameserver delegation has probably not propagated yet"
            )
        sleep(interval)


def delete_certificate(acm, certificate_arn: str) -> None:
    acm.delete_certificate(CertificateArn=certificate_arn)
