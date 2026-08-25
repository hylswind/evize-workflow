"""The signed statement and its digest.

The statement is both the attestation subject and its predicate, so its exact
bytes are the contract a verifier checks. Key order is part of that contract:
json.dumps preserves insertion order and the tests pin it.
"""

import hashlib
import json

BYPASS_KEYS = ("eventCheck", "domainTransfer")

STATEMENT_KEYS = (
    "accountID",
    "domain",
    "start",
    "holdSeconds",
    "repoID",
    "debug",
    "bypasses",
)


def build_bypasses(*, event_check: bool, domain_transfer: bool) -> dict:
    return {"eventCheck": bool(event_check), "domainTransfer": bool(domain_transfer)}


def build_statement(
    *,
    account_id: str,
    domain: str,
    start: int,
    hold_seconds: int,
    repo_id: int,
    bypasses: dict,
) -> dict:
    """Assemble the statement.

    `debug` is derived, never passed: any bypass makes the run a rehearsal, and
    deriving it here means a new bypass cannot be added without flipping it.
    """
    unknown = set(bypasses) - set(BYPASS_KEYS)
    if unknown:
        raise ValueError(f"unknown bypass keys: {sorted(unknown)}")
    normalised = {key: bool(bypasses.get(key, False)) for key in BYPASS_KEYS}
    return {
        "accountID": account_id,
        "domain": domain,
        "start": int(start),
        "holdSeconds": int(hold_seconds),
        "repoID": int(repo_id),
        "debug": any(normalised.values()),
        "bypasses": normalised,
    }


def serialise(statement: dict) -> str:
    return json.dumps(statement, indent=2) + "\n"


def write_statement(path, statement: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(serialise(statement))


def digest_file(path) -> str:
    """sha256 of the file on disk, formatted the way attestation subjects are."""
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return f"sha256:{hasher.hexdigest()}"
