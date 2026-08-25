"""Clients for the bring-up.

The instance carries the admin role through its instance profile, so there are
no keys here — boto3 picks the role up from the instance metadata.
"""

import boto3

from . import config


def session(region: str = None) -> boto3.Session:
    return boto3.Session(region_name=region or config.REGION)
