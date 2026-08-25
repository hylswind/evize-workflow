"""Root's last act.

After this the account holds no credential any human was given. UserName is
omitted because root is not an IAM user; the API infers the caller from the
signature.
"""

from enclavize.aws import iam


def delete_root_key(iam_client, root_key_id: str) -> None:
    iam.delete_access_key(iam_client, access_key_id=root_key_id)
