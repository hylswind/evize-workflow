"""Names both phases must agree on without talking to each other.

The workflow (in GitHub Actions) and the setup program (on the EC2 instance) run
in parallel and share no channel. They agree on the proof bucket by each deriving
its name from the account id, so this module is a contract: changing a name here
breaks the handover, and the offline tests pin it.
"""

# S3 bucket names must avoid dots: a dotted name cannot be reached over HTTPS with
# virtual-hosted-style addressing without certificate errors. The public name is a
# CloudFront alias (proof.{domain}), so the bucket name itself is never user-facing.
PROOF_BUCKET_PREFIX = "enclavize-proof"


def proof_bucket_name(account_id: str) -> str:
    """The bucket the workflow uploads proof to and the setup program creates.

    Derived rather than passed: the two phases run in parallel with no channel
    between them.
    """
    return f"{PROOF_BUCKET_PREFIX}-{account_id}"


def dashboard_bucket_name(account_id: str) -> str:
    return f"enclavize-dashboard-{account_id}"


def dashboard_host(domain: str) -> str:
    return f"dashboard.{domain}"


def proof_host(domain: str) -> str:
    return f"proof.{domain}"


CALLER_REFERENCE_PREFIX = "enclavize-"
"""Stamped on the hosted zone and both distributions as they are created.

It is what a teardown has to go on. An account may already hold a zone for this
domain — a registrar creates one — or distributions of its own, and a domain
name alone cannot tell those apart from the ones this program made. Removing the
wrong one destroys something nobody can put back.
"""


def caller_reference(account_id: str, unique: str) -> str:
    """A creation stamp that says this program made the thing carrying it."""
    return f"{CALLER_REFERENCE_PREFIX}{account_id}-{unique}"


def is_ours(caller_reference_value: str) -> bool:
    return str(caller_reference_value or "").startswith(CALLER_REFERENCE_PREFIX)


def apply_host(domain: str) -> str:
    """Where commits are applied.

    A name of its own rather than the generated execute-api one, because the
    generated one is unknowable from outside: the account is sealed, so nobody
    can look it up. This name is derivable from the domain alone.
    """
    return f"apply.{domain}"
