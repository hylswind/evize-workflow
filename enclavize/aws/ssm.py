"""Parameter Store: the AMI lookup and the go flag.

The go flag is the account's starting gun — the setup instance blocks on it
until the workflow has finished sealing.
"""

from botocore.exceptions import ClientError


def get_parameter(ssm, name: str) -> str:
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def try_get_parameter(ssm, name: str):
    """The value, or None if it does not exist yet."""
    try:
        return get_parameter(ssm, name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ParameterNotFound":
            return None
        raise


def put_parameter(ssm, name: str, value: str, *, overwrite: bool = True) -> None:
    ssm.put_parameter(Name=name, Value=value, Type="String", Overwrite=overwrite)


def delete_parameter(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise
