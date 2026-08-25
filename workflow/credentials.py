"""The console user's sign-in details.

This is the one output carrying a live credential, so it is written the moment
the user exists — a failure later in the run still owes the operator the way in.
The workflow encrypts it before it ever becomes an artifact, and it is never
part of the signed statement.
"""

import json


def build_console_credentials(*, account_id: str, user_name: str, password: str, domain: str) -> dict:
    return {
        "signInUrl": f"https://{account_id}.signin.aws.amazon.com/console",
        "accountId": account_id,
        "userName": user_name,
        "password": password,
        "dashboard": f"https://dashboard.{domain}",
        "note": (
            "Billing, plus a view of which resources exist — not what is inside them. "
            "This account can list a bucket but cannot open an object, and cannot read "
            "a secret, a parameter or a database item. You will be asked to change this "
            "password on first sign-in. Console sign-in is restricted to this user; "
            "nothing else in the account can reach the console."
        ),
    }


def write_console_credentials(path, credentials: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(credentials, indent=2) + "\n")
