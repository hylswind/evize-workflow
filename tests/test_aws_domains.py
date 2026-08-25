"""The registrar. Every mutation is asynchronous, so the polling is the module."""

import pytest
from constants import DOMAIN, clock, no_sleep

from enclavize.aws import domains


class FakeDomains:
    """Replays a scripted sequence of operation statuses."""

    def __init__(self, statuses, message=None):
        self.statuses = list(statuses)
        self.message = message
        self.calls = []

    def accept_domain_transfer_from_another_aws_account(self, **kwargs):
        self.calls.append(("accept", kwargs))
        return {"OperationId": "op-1"}

    def update_domain_nameservers(self, **kwargs):
        self.calls.append(("update_ns", kwargs))
        return {"OperationId": "op-2"}

    def get_operation_detail(self, **kwargs):
        self.calls.append(("detail", kwargs))
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        detail = {"Status": status}
        if self.message:
            detail["Message"] = self.message
        return detail


def test_accepting_a_transfer_sends_only_domain_and_password():
    # The API takes no account id: the initiating side already named this
    # account, so this side only proves it holds the password.
    client = FakeDomains(["SUCCESSFUL"])
    domains.accept_transfer(client, domain=DOMAIN, password="secret")
    assert client.calls[0][1] == {"DomainName": DOMAIN, "Password": "secret"}


def test_a_successful_operation_returns():
    client = FakeDomains(["SUBMITTED", "IN_PROGRESS", "SUCCESSFUL"])
    status = domains.poll_operation(
        client, "op-1", poll_max=1800, interval=30, sleep=no_sleep, now=clock([0, 1, 2, 3])
    )
    assert status == "SUCCESSFUL"


@pytest.mark.parametrize("bad", ["ERROR", "FAILED"])
def test_a_failed_transfer_stops_the_run(bad):
    # This happens before anything irreversible, so failing here is recoverable
    # — unlike failing after the root key is gone.
    client = FakeDomains([bad], message="wrong password")
    with pytest.raises(RuntimeError, match="wrong password"):
        domains.poll_operation(client, "op-1", poll_max=1800, interval=30, sleep=no_sleep, now=clock([0, 1]))


def test_a_stuck_operation_times_out_rather_than_hanging():
    client = FakeDomains(["IN_PROGRESS"])
    with pytest.raises(TimeoutError, match="still IN_PROGRESS"):
        domains.poll_operation(
            client, "op-1", poll_max=1800, interval=30, sleep=no_sleep, now=clock([0, 5000])
        )


def test_accept_and_wait_polls_the_operation_it_started():
    client = FakeDomains(["SUCCESSFUL"])
    domains.accept_and_wait(
        client, domain=DOMAIN, password="s", poll_max=60, interval=5, sleep=no_sleep, now=clock([0, 1])
    )
    assert [name for name, _ in client.calls] == ["accept", "detail"]
    assert client.calls[1][1] == {"OperationId": "op-1"}


def test_nameservers_are_sent_in_the_shape_the_api_expects():
    client = FakeDomains(["SUCCESSFUL"])
    domains.update_nameservers(client, domain=DOMAIN, nameservers=["ns-1.example", "ns-2.example"])
    assert client.calls[0][1]["Nameservers"] == [
        {"Name": "ns-1.example"},
        {"Name": "ns-2.example"},
    ]


def test_updating_nameservers_waits_for_the_registrar():
    # The certificate cannot validate until this delegation has propagated, so
    # moving on early would guarantee a later timeout.
    client = FakeDomains(["IN_PROGRESS", "SUCCESSFUL"])
    domains.update_nameservers_and_wait(
        client, domain=DOMAIN, nameservers=["ns-1.example"], poll_max=1800, interval=30,
        sleep=no_sleep, now=clock([0, 1, 2]),
    )
    assert [name for name, _ in client.calls] == ["update_ns", "detail", "detail"]
