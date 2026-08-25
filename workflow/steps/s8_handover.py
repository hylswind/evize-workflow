"""Fire the go flag.

The instance has been blocked on this parameter since it booted. Writing it is
the moment the account starts running itself, and it uses the starter's
credentials because root's no longer exist.
"""

from enclavize.aws import ssm


def release(ssm_client, *, go_param: str, value: str) -> None:
    ssm.put_parameter(ssm_client, go_param, value)
