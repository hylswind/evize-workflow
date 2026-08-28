"""The check that the account's root email is at the domain it will own.

The whole seal rests on it. Setup publishes a null MX for the domain, which is
what kills the address a password reset goes to — and only if the address is
there. An account signed up with a mailbox somewhere else keeps that mailbox, so
root's password can still be reset while the statement says the account is
sealed.

Reading the address at all takes an organization: `account:GetPrimaryEmail` is
refused to a standalone account as root and as an administrator, with and
without an AccountId, and CloudTrail redacts the value out of the sign-up event.
So the run makes one, reads the address out of the creating call's own response,
and removes it again — standalone going in, standalone coming out.
"""

import pytest
from botocore.exceptions import ClientError
from constants import ACCOUNT_ID, DOMAIN

from enclavize.aws import organizations
from workflow.steps import s0_verify_email

OTHER = "999988887777"


def error(code, operation):
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


class FakeOrganizations:
    """One account's worth of Organizations, remembering what it was asked."""

    def __init__(self, *, existing=None, email=f"owner@{DOMAIN}", delete_fails=False):
        self.organization = existing   # {"account_id", "email"} or None
        self.email = email
        self.delete_fails = delete_fails
        self.calls = []

    def create_organization(self, FeatureSet):  # noqa: N803 - boto3's own name
        self.calls.append(("create", FeatureSet))
        if self.organization:
            raise error(organizations.ALREADY_IN_ORGANIZATION, "CreateOrganization")
        self.organization = {"account_id": ACCOUNT_ID, "email": self.email}
        return {"Organization": {"Id": "o-1", "MasterAccountId": ACCOUNT_ID,
                                 "MasterAccountEmail": self.email}}

    def describe_organization(self):
        self.calls.append(("describe", None))
        if not self.organization:
            raise error(organizations.NOT_IN_ORGANIZATION, "DescribeOrganization")
        return {"Organization": {"Id": "o-1",
                                 "MasterAccountId": self.organization["account_id"],
                                 "MasterAccountEmail": self.organization["email"]}}

    def delete_organization(self):
        self.calls.append(("delete", None))
        if self.delete_fails:
            raise error("ConcurrentModificationException", "DeleteOrganization")
        self.organization = None


def verify(orgs=None, **kwargs):
    orgs = orgs if orgs is not None else FakeOrganizations()
    said = []
    found = s0_verify_email.verify(
        orgs, account_id=ACCOUNT_ID, domain=kwargs.pop("domain", DOMAIN),
        log=said.append, sleep=lambda _s: None, **kwargs,
    )
    return found, orgs, said


# --- the address is where it has to be ------------------------------------


def test_an_address_at_the_domain_passes():
    found, orgs, _ = verify()
    assert found == DOMAIN
    assert [name for name, _ in orgs.calls] == ["create", "delete"]


def test_the_organization_is_the_smallest_one_that_answers():
    """Policy types are not wanted; the account is about to be sealed."""
    _, orgs, _ = verify()
    assert orgs.calls[0] == ("create", organizations.CONSOLIDATED_BILLING)


def test_the_account_is_standalone_again_afterwards():
    _, orgs, _ = verify()
    assert orgs.organization is None


def test_case_and_padding_do_not_decide_it():
    """AWS stores the address as typed, and a domain arriving from a workflow
    input has been through a shell."""
    found, _, _ = verify(FakeOrganizations(email=f"Owner@{DOMAIN.upper()} "))
    assert found == DOMAIN


def test_an_address_at_another_domain_is_refused():
    with pytest.raises(SystemExit, match="elsewhere.test"):
        verify(FakeOrganizations(email="owner@elsewhere.test"))


def test_a_lookalike_suffix_is_not_the_domain():
    """`notexample.com` ends with the domain without being it."""
    with pytest.raises(SystemExit, match="not"):
        verify(FakeOrganizations(email=f"owner@not{DOMAIN}"))


def test_a_subdomain_is_not_the_domain():
    """The null MX goes on the apex. A mailbox at mail.{domain} has its own MX
    and would survive."""
    with pytest.raises(SystemExit):
        verify(FakeOrganizations(email=f"owner@mail.{DOMAIN}"))


# --- what it leaves behind ------------------------------------------------


def test_a_refused_domain_still_removes_the_organization():
    """Otherwise the next attempt finds a leftover and refuses for that instead,
    which is a worse message about a worse state."""
    orgs = FakeOrganizations(email="owner@elsewhere.test")
    with pytest.raises(SystemExit):
        verify(orgs)
    assert orgs.organization is None
    assert [name for name, _ in orgs.calls] == ["create", "delete"]


def test_a_delete_that_will_not_work_warns_rather_than_stops():
    """Stopping would leave the same organization behind *and* an unsealed
    account."""
    orgs = FakeOrganizations(delete_fails=True)
    found, _, said = verify(orgs)
    assert found == DOMAIN
    assert any("could not remove the organization" in line for line in said)
    assert sum(1 for name, _ in orgs.calls if name == "delete") == s0_verify_email.DELETE_ATTEMPTS


# --- an account that is already in one ------------------------------------


def test_an_account_that_already_manages_one_is_refused():
    """Either made by hand — no longer part of the procedure — or the leftover
    of an attempt that died between creating and deleting."""
    orgs = FakeOrganizations(existing={"account_id": ACCOUNT_ID, "email": f"owner@{DOMAIN}"})
    with pytest.raises(SystemExit, match="already manages an organization"):
        verify(orgs)
    assert orgs.organization is not None, "must not delete one it did not create"


def test_an_organization_someone_else_manages_is_refused():
    """The email would be theirs, and their management account can reach in."""
    orgs = FakeOrganizations(existing={"account_id": OTHER, "email": f"someone@{DOMAIN}"})
    with pytest.raises(SystemExit, match=OTHER):
        verify(orgs)


def test_any_other_aws_error_is_not_swallowed():
    """A throttle or a permissions problem must not read as "already in one"."""
    class Throttled(FakeOrganizations):
        def create_organization(self, FeatureSet):  # noqa: N803
            raise error("TooManyRequestsException", "CreateOrganization")

    with pytest.raises(ClientError):
        verify(Throttled())
