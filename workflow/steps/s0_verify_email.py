"""Check the account's root email is at the domain it is about to be given.

The seal rests on this. Setup publishes a null MX for the domain, which is what
kills the address a password reset would go to — but only if the address is at
*that* domain. An account signed up with a mailbox somewhere else keeps that
mailbox, so root's password can still be reset and the account is not sealed at
all, while looking exactly as though it were.

It runs before anything is touched, so a mismatch costs nothing: the account is
still whole, and the operator can fix the address or hand the right domain.
"""

from enclavize.aws import organizations

PREPARE = (
    "Create an organization in this account first, from the AWS Organizations "
    "console — that is what makes the root email readable at all."
)


def domain_of(email: str) -> str:
    return str(email or "").rsplit("@", 1)[-1].strip().lower()


def verify(orgs_client, *, account_id: str, domain: str) -> str:
    """Return the root email's domain, or raise SystemExit saying why not."""
    try:
        management = organizations.management_account(orgs_client)
    except organizations.NotAnOrganization:
        raise SystemExit(f"enclavize: this account is in no organization. {PREPARE}") from None

    if management["account_id"] != account_id:
        raise SystemExit(
            f"enclavize: account {account_id} is a member of an organization managed by "
            f"{management['account_id']}, so the only email readable here belongs to that "
            "account rather than this one. Nothing can be checked against it."
        )

    found = domain_of(management["email"])
    if found != domain.strip().lower():
        raise SystemExit(
            f"enclavize: this account's root email is at {found!r}, not {domain!r}. "
            "Sealing it would publish a null MX for a domain its mailbox does not use, "
            "leaving the address live and root's password resettable."
        )
    return found
