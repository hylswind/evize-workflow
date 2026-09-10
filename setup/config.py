"""Constants and resource names for phase B.

proof_bucket_name is imported from the same module phase A uses: the two
programs run in parallel and never talk, so agreeing on that name is what makes
the proof handover work.
"""

from dataclasses import dataclass, replace

from enclavize.logic.naming import (  # re-exported: the cross-phase contract
    APPLIES_INDEX_PREFIX,
    APPLIES_MANIFEST_KEY,
    APPLIES_PREFIX,
    CHANGES_CACHE_CONTROL,
    apply_host,
    apply_param_name,
    dashboard_bucket_name,
    go_flag_param,
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

APPLY_API_PATH = "commits"
APPLY_STAGE = "v1"
COMMIT_PATTERN = "^[0-9a-f]{40}$"

# What an applied commit runs on. Its own constants rather than phase A's: the
# two programs never talk, so neither can read the other's config.
AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
APPLY_INSTANCE_TYPE = "t3.large"

# The handshake before a version is replaced. While one is serving, an apply
# first runs the serving commit again on a preparing instance, in UPDATE mode,
# and only launches the new commit once that instance has said it is ready —
# or once this long has passed without a word. A timer looks every so often.
# Both are baked into the account at bring-up, so a change here takes effect on
# the next account sealed, not on one already running.
PREPARE_CHECK_INTERVAL_MINUTES = 5
PREPARE_TIMEOUT_SECONDS = 7 * 24 * 3600


@dataclass(frozen=True)
class Resources:
    prefix: str = "enclavize-"
    admin_role: str = "enclavize-admin"
    starter_user: str = "enclavize-starter"
    apply_role: str = "enclavize-apply"
    apply_boundary: str = "enclavize-apply-boundary"
    apply_sfn_role: str = "enclavize-apply-sfn"
    apply_api_role: str = "enclavize-apply-api"
    apply_scheduler_role: str = "enclavize-apply-scheduler"
    apply_state_machine: str = "enclavize-apply"
    apply_check_state_machine: str = "enclavize-apply-check"
    apply_check_schedule: str = "enclavize-apply-check"
    apply_api_name: str = "enclavize-apply-api"
    apply_current_param: str = "/enclavize/apply/current"
    apply_pending_param: str = "/enclavize/apply/pending"
    apply_ready_param: str = "/enclavize/apply/ready"

    def with_prefix(self, prefix: str) -> "Resources":
        renamed = {}
        for field_name in (
            "admin_role",
            "starter_user",
            "apply_role",
            "apply_boundary",
            "apply_sfn_role",
            "apply_api_role",
            "apply_scheduler_role",
            "apply_state_machine",
            "apply_check_state_machine",
            "apply_check_schedule",
            "apply_api_name",
        ):
            current = getattr(self, field_name)
            renamed[field_name] = prefix + current[len(self.prefix):] if current.startswith(self.prefix) else prefix + current
        renamed["prefix"] = prefix
        for which in ("current", "pending", "ready"):
            renamed[f"apply_{which}_param"] = apply_param_name(prefix, which)
        return replace(self, **renamed)

    def apply_boundary_arn(self, account_id: str) -> str:
        return f"arn:aws:iam::{account_id}:policy/{self.apply_boundary}"

    def go_param(self) -> str:
        """The workflow's starting gun, which lives under the same path. Named
        here so the boundary can keep applications away from it."""
        return go_flag_param(self.prefix)

    def enclave_params(self) -> list:
        """The parameters an application may neither read nor write: the go
        flag and the two that say what is serving and what is coming. The
        ready flag is absent on purpose — it is the one an application writes."""
        return [self.go_param(), self.apply_current_param, self.apply_pending_param]


RESOURCES = Resources()

__all__ = [
    "RESOURCES",
    "Resources",
    "APPLIES_INDEX_PREFIX",
    "APPLIES_MANIFEST_KEY",
    "APPLIES_PREFIX",
    "CHANGES_CACHE_CONTROL",
    "proof_bucket_name",
    "dashboard_bucket_name",
    "dashboard_host",
    "proof_host",
    "apply_host",
]
