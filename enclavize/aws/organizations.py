"""The one place an account can learn its own root email address.

There is no other. `account:GetPrimaryEmail` is refused to a standalone account
whether it asks as root or as an administrator, and with or without an AccountId
— the API answers only for a *member* of an organization, asked by that
organization's management account. CloudTrail is no help either: the sign-up
event carries an emailAddress field and AWS redacts its value.

An organization's own description, however, names the management account and its
email — and `DescribeOrganization` takes no arguments at all, so there is no "my
own account id" for it to refuse. So the run makes one, reads the address out of
the creating call's own response, and removes it again.

Organizations is global and answers through us-east-1.
"""

from botocore.exceptions import ClientError

NOT_IN_ORGANIZATION = "AWSOrganizationsNotInUseException"
ALREADY_IN_ORGANIZATION = "AlreadyInOrganizationException"

CONSOLIDATED_BILLING = "CONSOLIDATED_BILLING"
"""The minimal feature set. Nothing here wants policy types — the account is
about to be sealed, and an organization that exists for one read should carry as
little as it can."""


class NotAnOrganization(Exception):
    """This account is not in an organization, so its root email cannot be read."""


class AlreadyInOne(Exception):
    """This account is already in an organization, so one cannot be created."""


def management_account(orgs) -> dict:
    """The account that manages this organization, and the email it signs in as.

    Returns the id alongside the address on purpose. In an organization this
    account did not create, the email belongs to whoever did — comparing it to
    anything would be comparing somebody else's mailbox.
    """
    try:
        organization = orgs.describe_organization()["Organization"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == NOT_IN_ORGANIZATION:
            raise NotAnOrganization() from exc
        raise
    return {
        "account_id": organization["MasterAccountId"],
        "email": organization["MasterAccountEmail"],
    }


def create(orgs, *, feature_set: str = CONSOLIDATED_BILLING) -> dict:
    """Make this account the management account of a new organization.

    The email comes out of this call's own response, so nothing has to be read
    back and there is no consistency to wait on. Refuses an account that is
    already in one, which is how the caller learns its precondition failed
    without having to look first.
    """
    try:
        organization = orgs.create_organization(FeatureSet=feature_set)["Organization"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == ALREADY_IN_ORGANIZATION:
            raise AlreadyInOne() from exc
        raise
    return {
        "account_id": organization["MasterAccountId"],
        "email": organization["MasterAccountEmail"],
    }


def delete(orgs) -> None:
    """Put the account back to standalone.

    `AWSServiceRoleForOrganizations` is still there immediately afterwards and
    goes on its own later. Nothing here waits for that or removes it: a
    service-linked role is assumable by one AWS service and by no person, and
    `DeleteServiceLinkedRole` is asynchronous — the run would have to block on a
    deletion task or risk sealing the account with one still pending, after
    which nothing could finish it.
    """
    orgs.delete_organization()
