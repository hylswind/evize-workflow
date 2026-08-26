"""Constants and resource names for phase A.

Every name lives on Resources rather than as a module global so a test can take
a copy with a unique prefix, create the real things in a real account, and then
delete them by that prefix. config supplies defaults; it is never read from
inside a step.
"""

from dataclasses import dataclass, replace

from enclavize.logic.naming import proof_bucket_name  # re-exported: the cross-phase contract

REGION = "us-east-1"
"""Single region on purpose: sign-in policy writes must go to us-east-1, global
service events land there, and CloudFront certificates must live there."""

HOLD_SECONDS = 900
"""Long enough for the sealing actions to reach event history and the console
lockout to take effect.

Spent only when the history will be read. A run that bypasses the audit holds
for nothing instead, and its statement records that rather than this."""

DELIVERY_POLL_MAX_SECONDS = 1200
DELIVERY_POLL_INTERVAL = 30

TRANSFER_POLL_MAX_SECONDS = 1800
TRANSFER_POLL_INTERVAL = 30

PROOF_BUCKET_POLL_MAX_SECONDS = 900
PROOF_BUCKET_POLL_INTERVAL = 15
"""How long the workflow waits for the setup program to create the proof bucket.
The two run in parallel; setup creates it first thing, so this is normally a few
minutes. Running out is a warning, not a failure."""

INSTANCE_PROFILE_WAIT_SECONDS = 90
INSTANCE_PROFILE_RETRY_INTERVAL = 3

BASE_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
INSTANCE_TYPE = "t3.small"

STATEMENT_FILE = "statement.json"
BUNDLE_FILE = "bundle.jsonl"
CONSOLE_FILE = "console.json"
CONSOLE_ARCHIVE = "console.7z"
PREDICATE_TYPE = "https://enclavize.dev/enclaved-account/v1"

HANDOVER_FILE = ".enclavize-publish.json"
"""Carries the starter credentials from the sealing run to the publish step.
On disk rather than in GITHUB_ENV, which every later step can read. Never
uploaded as an artifact."""

GO_PARAM = "/enclavize/go-flag"
GO_VALUE = "go"


@dataclass(frozen=True)
class Resources:
    """Names of everything enclavize creates.

    with_prefix gives a test its own namespace in a real account.
    """

    prefix: str = "enclavize-"
    admin_role: str = "enclavize-admin"
    event_reader_user: str = "enclavize-event-reader"
    starter_user: str = "enclavize-starter"
    console_user: str = "enclavize-console"
    apply_role: str = "enclavize-apply"
    apply_boundary: str = "enclavize-apply-boundary"
    instance_name_tag: str = "enclavize-instance"
    signin_lock_vpc_tag: str = "enclavize-signin-lock-vpc"
    signin_lock_vpc_cidr: str = "10.255.0.0/28"
    go_param: str = GO_PARAM

    def with_prefix(self, prefix: str) -> "Resources":
        """A copy with every name renamed, for isolated real-account tests."""
        renamed = {}
        for field_name in (
            "admin_role",
            "event_reader_user",
            "starter_user",
            "console_user",
            "apply_role",
            "apply_boundary",
            "instance_name_tag",
            "signin_lock_vpc_tag",
        ):
            current = getattr(self, field_name)
            renamed[field_name] = prefix + current[len(self.prefix):] if current.startswith(self.prefix) else prefix + current
        renamed["prefix"] = prefix
        renamed["go_param"] = f"/{prefix.strip('-')}/go-flag"
        return replace(self, **renamed)

    def instance_profile(self) -> str:
        """Instance profile shares the admin role's name, as in the old repo."""
        return self.admin_role

    def console_user_arn(self, account_id: str) -> str:
        return f"arn:aws:iam::{account_id}:user/{self.console_user}"

    def apply_boundary_arn(self, account_id: str) -> str:
        return f"arn:aws:iam::{account_id}:policy/{self.apply_boundary}"


RESOURCES = Resources()
