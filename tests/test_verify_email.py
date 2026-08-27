"""The check that the account's root email is at the domain it will own.

The whole seal rests on it. Setup publishes a null MX for the domain, which is
what kills the address a password reset goes to — and only if the address is
there. An account signed up with a mailbox somewhere else keeps that mailbox,
so root's password can still be reset while the statement says the account is
sealed.

Reading the address at all takes an organization: `account:GetPrimaryEmail` is
refused to a standalone account as root and as an administrator, with and
without an AccountId, and CloudTrail redacts the value out of the sign-up event.
`DescribeOrganization` takes no arguments, so there is no own-account-id for it
to refuse — which is why creating one is a manual step before a run.
"""

import pytest
from botocore.exceptions import ClientError
from constants import ACCOUNT_ID, DOMAIN

from enclavize.aws import organizations
from workflow.steps import s0_verify_email

OTHER = "999988887777"


class FakeOrganizations:
    def __init__(self, *, master=ACCOUNT_ID, email=f"owner@{DOMAIN}", error=None):
        self.master, self.email, self.error = master, email, error

    def describe_organization(self):
        if self.error:
            raise ClientError({"Error": {"Code": self.error, "Message": self.error}},
                              "DescribeOrganization")
        return {"Organization": {"Id": "o-1", "MasterAccountId": self.master,
                                 "MasterAccountEmail": self.email}}


def verify(**kwargs):
    return s0_verify_email.verify(FakeOrganizations(**kwargs), account_id=ACCOUNT_ID, domain=DOMAIN)


# --- the address is where it has to be ------------------------------------


def test_an_address_at_the_domain_passes():
    assert verify() == DOMAIN


def test_case_and_padding_do_not_decide_it():
    """AWS stores the address as typed, and a domain arriving from a workflow
    input has been through a shell."""
    assert verify(email=f"Owner@{DOMAIN.upper()} ") == DOMAIN


def test_an_address_at_another_domain_is_refused():
    with pytest.raises(SystemExit, match="elsewhere.test"):
        verify(email="owner@elsewhere.test")


def test_a_lookalike_suffix_is_not_the_domain():
    """`notexample.com` ends with the domain without being it."""
    with pytest.raises(SystemExit, match="not"):
        verify(email=f"owner@not{DOMAIN}")


def test_a_subdomain_is_not_the_domain():
    """The null MX goes on the apex. A mailbox at mail.{domain} has its own MX
    and would survive."""
    with pytest.raises(SystemExit):
        verify(email=f"owner@mail.{DOMAIN}")


# --- when the address cannot be read at all -------------------------------


def test_an_account_in_no_organization_is_told_how_to_prepare():
    """Nothing else in a standalone account will answer, so "cannot read it" is
    a missing preparation step rather than a failure to report."""
    with pytest.raises(SystemExit, match="Organizations console"):
        verify(error=organizations.NOT_IN_ORGANIZATION)


def test_an_organization_someone_else_manages_is_refused():
    """The email would be theirs. Comparing it to anything compares the wrong
    mailbox — and passing would be worse than failing."""
    with pytest.raises(SystemExit, match=OTHER):
        verify(master=OTHER, email=f"someone@{DOMAIN}")


def test_any_other_aws_error_is_not_swallowed():
    """Throttling or a permissions problem must not read as "no organization"
    and send the operator off to create one."""
    with pytest.raises(ClientError):
        verify(error="TooManyRequestsException")


# --- the module underneath ------------------------------------------------


def test_the_management_account_is_reported_with_its_id():
    found = organizations.management_account(FakeOrganizations())
    assert found == {"account_id": ACCOUNT_ID, "email": f"owner@{DOMAIN}"}
