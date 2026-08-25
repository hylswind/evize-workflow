"""Take ownership of the domain.

Runs before anything irreversible: a wrong password or an expired transfer
window fails here, while the account can still be used normally.

The hosted zone does not come with the domain — the setup program builds one and
points the registration at it later.
"""

from enclavize.aws import domains


def accept(r53d_client, *, domain: str, password: str, poll_max: int, interval: int) -> None:
    domains.accept_and_wait(
        r53d_client, domain=domain, password=password, poll_max=poll_max, interval=interval
    )
