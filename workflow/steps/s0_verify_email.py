"""Check the account's root email is at the domain it is about to be given.

The seal rests on this. Setup publishes a null MX for the domain, which is what
kills the address a password reset would go to — but only if the address is at
*that* domain. An account signed up with a mailbox somewhere else keeps that
mailbox, so root's password can still be reset and the account is not sealed at
all, while looking exactly as though it were.

Reading the address takes an organization, and nothing else in a standalone
account will answer — so this makes one, reads it, and removes it again. The
account is standalone going in and standalone coming out; anything else is
refused rather than worked around, including the organization this step made
itself failing to go. Stopping here is free — nothing irreversible has happened
yet — and it is the last moment that is true.
"""

import time

from enclavize.aws import organizations


def domain_of(email: str) -> str:
    return str(email or "").rsplit("@", 1)[-1].strip().lower()


def organization_refusal(management: dict, account_id: str) -> str:
    """Which of the two situations an account already in one is in.

    Public and pure because preflight refuses the same two before a cycle
    starts, and it is the operator who reads both: two wordings of one refusal
    drift, and the drift shows up at the worst moment.
    """
    if management["account_id"] == account_id:
        return (
            "this account already manages an organization. The run makes its own and "
            "removes it, so this is either one created by hand or the leftover of an "
            "attempt that died between the two. Delete it and run again."
        )
    return (
        f"account {account_id} is a member of an organization managed by "
        f"{management['account_id']}. The only email readable here is that account's, and "
        "its management account can reach into this one whatever enclavize does."
    )


def _already_in_one(orgs_client, account_id: str) -> SystemExit:
    """The run is failing either way; the difference decides what the operator
    does about it."""
    try:
        management = organizations.management_account(orgs_client)
    except organizations.NotAnOrganization:  # raced with a deletion; try again
        return SystemExit("enclavize: this account's organization changed mid-check; re-run")
    return SystemExit("enclavize: " + organization_refusal(management, account_id))


def _remove(orgs_client, *, attempts: int, interval: int, log, sleep):
    """Put the account back. Returns what stopped it, or None.

    Retried because a transient refusal must not be mistaken for one that will
    never work: this answer decides whether the run goes on, so it is worth
    asking more than once.
    """
    for attempt in range(1, attempts + 1):
        try:
            organizations.delete(orgs_client)
            return None
        except Exception as exc:  # noqa: BLE001 - handed back, not swallowed
            if attempt == attempts:
                return exc
            log(f"could not remove the organization ({exc}); retrying")
            sleep(interval)


def _left_behind(failure, mismatch: str) -> SystemExit:
    """Stop, while stopping is still free.

    Nothing irreversible has happened at this point — the domain has not moved,
    the console is open, root still holds its key — so the account can simply be
    put right and the run dispatched again. Carrying on is what cannot be undone:
    by the end root's key is deleted and the console locked, and then nothing
    left in the account can delete an organization. It would be sealed managing
    one, under a statement that says it is standalone.
    """
    lines = [
        f"enclavize: created an organization to read the root email and could not "
        f"remove it: {failure}",
        "The account still manages it. Nothing else has been touched — delete the "
        "organization and run again.",
    ]
    if mismatch:
        lines.append(f"Note for when you do: {mismatch}")
    return SystemExit("\n".join(lines))


def verify(orgs_client, *, account_id: str, domain: str, delete_attempts: int,
           delete_interval: int, log=print, sleep=time.sleep) -> str:
    """Return the root email's domain, or raise SystemExit saying why not."""
    try:
        email = organizations.create(orgs_client)
    except organizations.AlreadyInOne:
        raise _already_in_one(orgs_client, account_id) from None

    found = domain_of(email)
    mismatch = None if found == domain.strip().lower() else (
        f"this account's root email is at {found!r}, not {domain!r}. Sealing it would "
        "publish a null MX for a domain its mailbox does not use, leaving the address "
        "live and root's password resettable."
    )

    # Removed before either answer is given, so the account is standalone again
    # whichever way this ends — and a wrong domain never leaves an organization
    # behind to turn the next attempt into the leftover case above.
    failure = _remove(orgs_client, attempts=delete_attempts, interval=delete_interval,
                      log=log, sleep=sleep)
    if failure is not None:
        raise _left_behind(failure, mismatch)
    if mismatch:
        raise SystemExit("enclavize: " + mismatch)
    return found
