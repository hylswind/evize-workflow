"""The console lock. moto has no signin service, so the client is faked; the
real calls are exercised by tests/aws/test_signin.py."""

import pytest
from botocore.exceptions import ClientError
from constants import ACCOUNT_ID, REGION

from enclavize.aws import signin

CONSOLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/enclavize-console"


class FakeSignin:
    def __init__(self, statements=None):
        self.calls = []
        self.statements = statements or []

    def put_resource_permission_statement(self, **kwargs):
        self.calls.append(("put_statement", kwargs))
        return {"statementId": "stmt-1"}

    def put_console_authorization_configuration(self, **kwargs):
        self.calls.append(("enable", kwargs))
        return {}

    def delete_console_authorization_configuration(self, **kwargs):
        self.calls.append(("disable", kwargs))
        return {}

    def delete_resource_permission_statement(self, **kwargs):
        self.calls.append(("delete_statement", kwargs))
        return {}

    def list_resource_permission_statements(self, **kwargs):
        self.calls.append(("list", kwargs))
        if kwargs.get("nextToken") == "page2":
            return {signin.STATEMENTS_KEY: self.statements[1:]}
        if len(self.statements) > 1:
            return {signin.STATEMENTS_KEY: self.statements[:1], "nextToken": "page2"}
        return {signin.STATEMENTS_KEY: self.statements}


def lock(client):
    return signin.enable_lock(
        client,
        vpc_id="vpc-anchor",
        account_id=ACCOUNT_ID,
        region=REGION,
        excluded_principal=CONSOLE_ARN,
        client_token="token-1",
    )


def test_the_lock_anchors_on_a_vpc_nothing_can_reach():
    client = FakeSignin()
    lock(client)
    _, kwargs = client.calls[0]
    assert kwargs["sourceVpc"] == "vpc-anchor"
    assert kwargs["requestedRegion"] == REGION


def test_only_the_console_user_is_exempt():
    client = FakeSignin()
    lock(client)
    _, kwargs = client.calls[0]
    assert kwargs["excludedPrincipal"] == CONSOLE_ARN


def test_enforcement_is_switched_on_after_the_statement_exists():
    # A statement alone does nothing; enabling first would be a window where the
    # account enforces a policy that has not been written.
    client = FakeSignin()
    lock(client)
    assert [name for name, _ in client.calls] == ["put_statement", "enable"]
    assert client.calls[1][1] == {"targetId": ACCOUNT_ID}


def test_the_statement_id_is_returned_so_it_can_be_undone():
    assert lock(FakeSignin()) == "stmt-1"


def test_disable_turns_enforcement_off_before_removing_the_statement():
    # The reverse order would briefly enforce a statement that no longer exists.
    client = FakeSignin()
    signin.disable_lock(client, account_id=ACCOUNT_ID, statement_id="stmt-1", client_token="t")
    assert [name for name, _ in client.calls] == ["disable", "delete_statement"]


def test_disable_works_when_only_the_configuration_was_applied():
    # A run that failed between the two calls still has to be recoverable.
    client = FakeSignin()
    signin.disable_lock(client, account_id=ACCOUNT_ID)
    assert [name for name, _ in client.calls] == ["disable"]


def test_the_statement_still_goes_when_the_configuration_is_already_absent():
    """Calling this twice is the normal way a half-finished recovery finishes.
    An absent configuration is not a reason to leave its statement behind."""

    class ConfigurationAlreadyGone(FakeSignin):
        def delete_console_authorization_configuration(self, **kwargs):
            self.calls.append(("disable", kwargs))
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}},
                "DeleteConsoleAuthorizationConfiguration",
            )

    client = ConfigurationAlreadyGone()
    signin.disable_lock(client, account_id=ACCOUNT_ID, statement_id="stmt-1")
    assert [name for name, _ in client.calls] == ["disable", "delete_statement"]


def test_a_real_failure_disabling_still_stops_the_teardown():
    class Denied(FakeSignin):
        def delete_console_authorization_configuration(self, **kwargs):
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                "DeleteConsoleAuthorizationConfiguration",
            )

    with pytest.raises(ClientError):
        signin.disable_lock(Denied(), account_id=ACCOUNT_ID, statement_id="stmt-1")


def test_listing_statements_follows_pagination():
    # Recovery needs every statement, not just the first page.
    client = FakeSignin(statements=[{"statementId": "a"}, {"statementId": "b"}])
    assert [s["statementId"] for s in signin.list_statements(client)] == ["a", "b"]


def test_the_statements_key_matches_what_the_service_actually_sends():
    """Pinned against botocore's own model, because the failure is silent.

    Reading a key sign-in does not send yields an empty list, and an empty list
    reads as an unlocked account — so a wrong name here would have the teardown
    leave the console locked and every check report the account clean.
    """
    import boto3

    model = boto3.client("signin", region_name=REGION).meta.service_model
    output = model.operation_model("ListResourcePermissionStatements").output_shape
    assert signin.STATEMENTS_KEY in output.members, sorted(output.members)


def test_a_listed_statement_names_its_id_differently_from_the_write_calls():
    """Put and Delete both say statementId; only the listing says sid. Reading
    the wrong one yields None, and disable_lock treats None as 'no statement to
    remove' — enforcement goes off and the statement stays behind."""
    import boto3

    model = boto3.client("signin", region_name=REGION).meta.service_model
    listed = model.operation_model("ListResourcePermissionStatements").output_shape
    item = listed.members[signin.STATEMENTS_KEY].member
    assert signin.STATEMENT_ID_KEY in item.members, sorted(item.members)

    delete = model.operation_model("DeleteResourcePermissionStatement").input_shape
    assert "statementId" in delete.members
    assert signin.statement_id({signin.STATEMENT_ID_KEY: "abc"}) == "abc"
    assert signin.statement_id({}) == ""


def test_an_account_with_no_statements_lists_nothing_rather_than_failing():
    """Sign-in answers ResourceNotFoundException when nothing has ever been
    configured, rather than returning an empty list. Callers are asking what is
    configured, and 'nothing' is an answer."""

    class NeverConfigured:
        def list_resource_permission_statements(self, **_kwargs):
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException",
                           "Message": "Requested resource not found"}},
                "ListResourcePermissionStatements",
            )

    assert signin.list_statements(NeverConfigured()) == []


def test_any_other_error_still_propagates():
    """Swallowing everything would turn a denied call into 'no lock present',
    which is precisely the wrong answer for a check that gates a run."""

    class Denied:
        def list_resource_permission_statements(self, **_kwargs):
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                "ListResourcePermissionStatements",
            )

    with pytest.raises(ClientError):
        signin.list_statements(Denied())


def test_the_recovery_hint_names_the_account_and_the_write_region():
    hint = signin.recovery_hint(ACCOUNT_ID)
    assert ACCOUNT_ID in hint
    assert "--region us-east-1" in hint
    assert "delete-console-authorization-configuration" in hint


def test_the_recovery_hint_explains_why_the_cli_still_works():
    # Anyone reading this is locked out of the console and needs to know that
    # programmatic access is unaffected.
    assert "SigV4" in signin.recovery_hint(ACCOUNT_ID)
