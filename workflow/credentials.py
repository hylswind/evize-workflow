"""The console user's sign-in details.

This is the one output carrying a live credential, so it is written the moment
the user exists — a failure later in the run still owes the operator the way in.
The workflow encrypts it before it ever becomes an artifact, and it is never
part of the signed statement.
"""

import json


def build_console_credentials(*, account_id: str, user_name: str, password: str) -> dict:
    """Only what signing in needs: where, as whom, with what.

    The account id is in the sign-in URL already, and what this user can see
    once inside is the README's to describe rather than this file's.
    """
    return {
        "signInUrl": f"https://{account_id}.signin.aws.amazon.com/console",
        "userName": user_name,
        "password": password,
    }


def write_console_credentials(path, credentials: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(credentials, indent=2) + "\n")
