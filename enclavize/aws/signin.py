"""The console lock.

Sign-in policies gate interactive console access only; requests signed with
SigV4 are never affected. That asymmetry is what makes the lock safe to apply
and safe to test: a programmatic caller can always undo it, so a half-finished
attempt can be recovered from the CLI.

The lock names an anchor VPC that nothing can originate from, so every principal
is denied except the one console user named as excluded. Write operations must
go to us-east-1; the policy then replicates globally over a few minutes.
"""

from botocore.exceptions import ClientError

WRITE_REGION = "us-east-1"


def enable_lock(signin, *, vpc_id: str, account_id: str, region: str, excluded_principal: str,
                client_token: str) -> str:
    """Deny console sign-in except from an unreachable VPC. Returns statement id.

    Two calls: the statement describes the restriction, and the configuration
    turns enforcement on. A statement alone does nothing until enabled.
    """
    response = signin.put_resource_permission_statement(
        sourceVpc=vpc_id,
        requestedRegion=region,
        excludedPrincipal=excluded_principal,
        clientToken=client_token,
    )
    statement_id = response.get("statementId") or response.get("StatementId")
    signin.put_console_authorization_configuration(targetId=account_id)
    return statement_id


def list_statements(signin) -> list:
    """Every permission statement on the account. None is an empty list.

    Needed to undo a lock whose statement id was not kept — which is how the
    recovery path and the real-account test clean up.

    An account that has never had a statement raises ResourceNotFoundException
    rather than answering with nothing, so that is translated here: callers ask
    what is configured, and "nothing" is an answer, not a failure.
    """
    found = []
    token = None
    while True:
        kwargs = {"maxResults": 50}
        if token:
            kwargs["nextToken"] = token
        try:
            response = signin.list_resource_permission_statements(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return found
            raise
        found.extend(response.get("resourcePermissionStatements", []))
        token = response.get("nextToken")
        if not token:
            return found


def disable_lock(signin, *, account_id: str, statement_id: str = None, client_token: str = None) -> None:
    """Undo the lock. Safe to call when only partly applied.

    Enforcement is switched off before the statement is removed, so the account
    is never left enforcing a statement that has gone.
    """
    signin.delete_console_authorization_configuration(targetId=account_id)
    if statement_id:
        kwargs = {"statementId": statement_id}
        if client_token:
            kwargs["clientToken"] = client_token
        signin.delete_resource_permission_statement(**kwargs)


def recovery_hint(account_id: str) -> str:
    """The command a locked-out operator needs. Printed on failure."""
    return (
        "console sign-in may still be restricted. Undo it with programmatic "
        "credentials (sign-in policies never apply to SigV4 API calls):\n"
        f"  aws signin delete-console-authorization-configuration --target-id {account_id} --region {WRITE_REGION}\n"
        f"  aws signin list-resource-permission-statements --region {WRITE_REGION}\n"
        f"  aws signin delete-resource-permission-statement --statement-id <id> --region {WRITE_REGION}"
    )
