"""The one place an account can learn its own root email address.

There is no other. `account:GetPrimaryEmail` is refused to a standalone account
whether it asks as root or as an administrator, and with or without an AccountId
— the API answers only for a *member* of an organization, asked by that
organization's management account. CloudTrail is no help either: the sign-up
event carries an emailAddress field and AWS redacts its value.

An organization's own description, however, names the management account and its
email — and `DescribeOrganization` takes no arguments at all, so there is no "my
own account id" for it to refuse. That is why creating an organization is one of
the manual steps before a run: it is what makes the address readable.

Organizations is global and answers through us-east-1.
"""

from botocore.exceptions import ClientError

NOT_IN_ORGANIZATION = "AWSOrganizationsNotInUseException"


class NotAnOrganization(Exception):
    """This account is not in an organization, so its root email cannot be read."""


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
