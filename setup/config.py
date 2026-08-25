"""Constants and resource names for phase B.

proof_bucket_name is imported from the same module phase A uses: the two
programs run in parallel and never talk, so agreeing on that name is what makes
the proof handover work.
"""

from dataclasses import dataclass, replace

from enclavize.logic.naming import (  # re-exported: the cross-phase contract
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

# RFC 7505: a single "." exchanger declares the domain accepts no mail, which is
# what makes the account's root email address dead.
NULL_MX_VALUE = "0 ."

DEPLOY_API_PATH = "deployments"
DEPLOY_STAGE = "v1"
COMMIT_PATTERN = "^[0-9a-f]{40}$"


@dataclass(frozen=True)
class Resources:
    prefix: str = "enclavize-"
    admin_role: str = "enclavize-admin"
    starter_user: str = "enclavize-starter"
    deploy_role: str = "enclavize-deploy"
    deploy_boundary: str = "enclavize-deploy-boundary"
    deploy_sfn_role: str = "enclavize-deploy-sfn"
    deploy_api_role: str = "enclavize-deploy-api"
    deploy_state_machine: str = "enclavize-deploy"
    deploy_api_name: str = "enclavize-deploy-api"

    def with_prefix(self, prefix: str) -> "Resources":
        renamed = {}
        for field_name in (
            "admin_role",
            "starter_user",
            "deploy_role",
            "deploy_boundary",
            "deploy_sfn_role",
            "deploy_api_role",
            "deploy_state_machine",
            "deploy_api_name",
        ):
            current = getattr(self, field_name)
            renamed[field_name] = prefix + current[len(self.prefix):] if current.startswith(self.prefix) else prefix + current
        renamed["prefix"] = prefix
        return replace(self, **renamed)

    def deploy_boundary_arn(self, account_id: str) -> str:
        return f"arn:aws:iam::{account_id}:policy/{self.deploy_boundary}"


RESOURCES = Resources()

__all__ = [
    "RESOURCES",
    "Resources",
    "proof_bucket_name",
    "dashboard_bucket_name",
    "dashboard_host",
    "proof_host",
]
