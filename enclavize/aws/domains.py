"""The domain registrar.

Route 53 Domains is a global service reached through us-east-1. Every mutation
is asynchronous: the call returns an operation id and the real outcome only
appears by polling it.

Note that transferring a domain between accounts does not bring its hosted zone
along, so the receiving account has to build its own zone and then point the
registration at it.
"""

import time

REGION = "us-east-1"
"""Route 53 Domains is global but answers only here, so every client naming it
says so. Named rather than repeated, as signin.WRITE_REGION is."""

TERMINAL_OK = "SUCCESSFUL"
TERMINAL_BAD = ("ERROR", "FAILED")


def accept_transfer(r53d, *, domain: str, password: str) -> str:
    """Accept a transfer another account initiated. Returns an operation id.

    Takes no account id: the initiating side named this account, and this side
    only proves it holds the password.
    """
    return r53d.accept_domain_transfer_from_another_aws_account(
        DomainName=domain, Password=password
    )["OperationId"]


def update_nameservers(r53d, *, domain: str, nameservers) -> str:
    """Point the registration at a hosted zone's delegation set."""
    return r53d.update_domain_nameservers(
        DomainName=domain,
        Nameservers=[{"Name": name} for name in nameservers],
    )["OperationId"]


def poll_operation(r53d, operation_id: str, *, poll_max: int, interval: int,
                   sleep=time.sleep, now=time.monotonic) -> str:
    """Wait for an operation to finish. Raises unless it succeeded.

    A failed transfer has to stop the run: it happens before anything
    irreversible, so failing here is recoverable.
    """
    deadline = now() + poll_max
    while True:
        detail = r53d.get_operation_detail(OperationId=operation_id)
        status = detail.get("Status")
        if status == TERMINAL_OK:
            return status
        if status in TERMINAL_BAD:
            message = detail.get("Message") or "no reason given"
            raise RuntimeError(f"enclavize: domain operation {operation_id} ended {status}: {message}")
        if now() >= deadline:
            raise TimeoutError(
                f"enclavize: domain operation {operation_id} still {status} after {poll_max}s"
            )
        sleep(interval)


def accept_and_wait(r53d, *, domain: str, password: str, poll_max: int, interval: int,
                    sleep=time.sleep, now=time.monotonic) -> None:
    operation_id = accept_transfer(r53d, domain=domain, password=password)
    poll_operation(r53d, operation_id, poll_max=poll_max, interval=interval, sleep=sleep, now=now)


def update_nameservers_and_wait(r53d, *, domain: str, nameservers, poll_max: int, interval: int,
                                sleep=time.sleep, now=time.monotonic) -> None:
    operation_id = update_nameservers(r53d, domain=domain, nameservers=nameservers)
    poll_operation(r53d, operation_id, poll_max=poll_max, interval=interval, sleep=sleep, now=now)
