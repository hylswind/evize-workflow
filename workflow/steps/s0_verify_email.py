"""Check the account's root email is at the domain it is about to be given.

The seal rests on this. Setup publishes a null MX for the domain, which is what
kills the address a password reset would go to — but only if the address is at
*that* domain. An account signed up with a mailbox somewhere else keeps that
mailbox, so root's password can still be reset and the account is not sealed at
all, while looking exactly as though it were.

Reading the address takes an organization, and nothing else in a standalone
account will answer — so this makes one, reads it, and removes it again. The
account is standalone going in and standalone coming out; anything else is
refused rather than worked around.
"""

import time

from enclavize.aws import organizations

DELETE_ATTEMPTS = 3
DELETE_INTERVAL = 5


def domain_of(email: str) -> str:
    return str(email or "").rsplit("@", 1)[-1].strip().lower()


def _already_in_one(orgs_client, account_id: str) -> SystemExit:
    """Say which of the two situations this is. The run is failing either way;
    the difference decides what the operator does about it."""
    try:
        management = organizations.management_account(orgs_client)
    except organizations.NotAnOrganization:  # raced with a deletion; try again
        return SystemExit("enclavize: this account's organization changed mid-check; re-run")

    if management["account_id"] == account_id:
        return SystemExit(
            "enclavize: this account already manages an organization. The run makes its "
            "own and removes it, so this is either one created by hand or the leftover of "
            "an attempt that died between the two. Delete it and run again."
        )
    return SystemExit(
        f"enclavize: account {account_id} is a member of an organization managed by "
        f"{management['account_id']}. The only email readable here is that account's, and "
        "its management account can reach into this one whatever enclavize does."
    )


def _remove(orgs_client, log, sleep) -> None:
    """Put the account back, and never let this be why a run stops.

    Failing here would leave the organization behind *and* an unsealed account,
    which is worse than an empty organization the account manages.
    """
    for attempt in range(1, DELETE_ATTEMPTS + 1):
        try:
            organizations.delete(orgs_client)
            return
        except Exception as exc:  # noqa: BLE001 - reported, never raised
            if attempt == DELETE_ATTEMPTS:
                log(f"WARNING: could not remove the organization this run created: {exc}")
                log("WARNING: the account still manages it; delete it before the next run")
                return
            sleep(DELETE_INTERVAL)


def verify(orgs_client, *, account_id: str, domain: str, log=print, sleep=time.sleep) -> str:
    """Return the root email's domain, or raise SystemExit saying why not."""
    try:
        made = organizations.create(orgs_client)
    except organizations.AlreadyInOne:
        raise _already_in_one(orgs_client, account_id) from None

    try:
        found = domain_of(made["email"])
        if found != domain.strip().lower():
            raise SystemExit(
                f"enclavize: this account's root email is at {found!r}, not {domain!r}. "
                "Sealing it would publish a null MX for a domain its mailbox does not use, "
                "leaving the address live and root's password resettable."
            )
        return found
    finally:
        # Runs on the refusal too: a wrong domain must not leave an organization
        # behind and turn the next attempt into the leftover case above.
        _remove(orgs_client, log, sleep)
