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


APPLIES_PREFIX = "applies/"
"""Where each apply is recorded, under `{startedAt}_{commit}.json`.

The timestamp leads so the keys sort in the order things happened, which is what
lets one month be listed by prefix alone. The underscore separates them because
it is the one character an ISO timestamp does not already contain.
"""

APPLIES_INDEX_PREFIX = "applies/index/"
"""One shard per month, `{YYYY-MM}.json`, holding that month's listing.

Deliberately below a path no month prefix can reach: `applies/2026-08` cannot
match `applies/index/…`, so listing a month never picks up a shard.
"""

APPLIES_MANIFEST_KEY = "applies.json"
"""Which months hold applies. The dashboard reads this first, opens the newest
month, and walks back from there — which is how the whole history stays
reachable without any single file having to hold it."""

CHANGES_CACHE_CONTROL = "no-cache"
"""For the few objects that are rewritten: the status, the manifest, the shard
for the current month.

The distribution's cache policy has a minimum TTL of one second, which it
applies in place of no-cache — so this is a second of staleness rather than the
policy's default day. A second is nothing; a day would outlast the bring-up or
the apply it is meant to report. Everything else in the bucket is written once
and never again, where a day's caching is exactly right.
"""


def apply_record_key(started_at: str, commit: str) -> str:
    """The key one apply is recorded under."""
    return f"{APPLIES_PREFIX}{started_at}_{commit}.json"


def apply_month_prefix(month: str) -> str:
    """Everything applied in one month, as an S3 prefix."""
    return f"{APPLIES_PREFIX}{month}"


def apply_month_key(month: str) -> str:
    return f"{APPLIES_INDEX_PREFIX}{month}.json"


def apply_host(domain: str) -> str:
    """Where commits are applied.

    A name of its own rather than the generated execute-api one, because the
    generated one is unknowable from outside: the account is sealed, so nobody
    can look it up. This name is derivable from the domain alone.
    """
    return f"apply.{domain}"
