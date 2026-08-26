"""Constants and resource names for phase B.

proof_bucket_name is imported from the same module phase A uses: the two
programs run in parallel and never talk, so agreeing on that name is what makes
the proof handover work.
"""

from dataclasses import dataclass, replace

from enclavize.logic.naming import (  # re-exported: the cross-phase contract
    apply_host,
    dashboard_bucket_name,
    dashboard_host,
    proof_bucket_name,
    proof_host,
)

REGION = "us-east-1"

# The workflow is waiting on the proof bucket, so it is created before the slow
# DNS/ACM/CloudFront path begins.
PROOF_OBJECT_POLL_MAX_SECONDS = 3600
PROOF_OBJECT_POLL_INTERVAL = 30

NS_OPERATION_POLL_MAX_SECONDS = 1800
NS_OPERATION_POLL_INTERVAL = 30

# Certificate validation cannot succeed until the registrar's new delegation has
# propagated, which is the longest wait in the whole bring-up.
CERT_VALIDATION_POLL_MAX_SECONDS = 2700
CERT_VALIDATION_POLL_INTERVAL = 30

DISTRIBUTION_POLL_MAX_SECONDS = 1800
DISTRIBUTION_POLL_INTERVAL = 30

RECORD_SYNC_POLL_MAX_SECONDS = 600
RECORD_SYNC_POLL_INTERVAL = 15

STATEMENT_KEY = "statement.json"
BUNDLE_KEY = "bundle.jsonl"
INDEX_KEY = "index.html"
STATUS_KEY = "status.json"

STATUS_CACHE_CONTROL = "no-cache"
"""The distribution's cache policy has a minimum TTL of one second, which it
applies in place of no-cache — so this is a second of staleness rather than the
policy's default day. A second is nothing; a day would outlast the bring-up it
is meant to report on."""

# RFC 7505: a single "." exchanger declares the domain accepts no mail, which is
# what makes the account's root email address dead.
NULL_MX_VALUE = "0 ."

APPLY_API_PATH = "commits"
APPLY_STAGE = "v1"
COMMIT_PATTERN = "^[0-9a-f]{40}$"


@dataclass(frozen=True)
class Resources:
    prefix: str = "enclavize-"
    admin_role: str = "enclavize-admin"
    starter_user: str = "enclavize-starter"
    apply_role: str = "enclavize-apply"
    apply_boundary: str = "enclavize-apply-boundary"
    apply_sfn_role: str = "enclavize-apply-sfn"
    apply_api_role: str = "enclavize-apply-api"
    apply_state_machine: str = "enclavize-apply"
    apply_api_name: str = "enclavize-apply-api"

    def with_prefix(self, prefix: str) -> "Resources":
        renamed = {}
        for field_name in (
            "admin_role",
            "starter_user",
            "apply_role",
            "apply_boundary",
            "apply_sfn_role",
            "apply_api_role",
            "apply_state_machine",
            "apply_api_name",
        ):
            current = getattr(self, field_name)
            renamed[field_name] = prefix + current[len(self.prefix):] if current.startswith(self.prefix) else prefix + current
        renamed["prefix"] = prefix
        return replace(self, **renamed)

    def apply_boundary_arn(self, account_id: str) -> str:
        return f"arn:aws:iam::{account_id}:policy/{self.apply_boundary}"


RESOURCES = Resources()

__all__ = [
    "RESOURCES",
    "Resources",
    "proof_bucket_name",
    "dashboard_bucket_name",
    "dashboard_host",
    "proof_host",
    "apply_host",
]
