"""Close the console.

An empty VPC is created purely to be named as the only permitted source of
sign-in traffic; since nothing can ever originate from it, every principal is
denied except the console user named as excluded.

A fresh VPC every time, deliberately: reusing a tagged one would silently accept
an account somebody had already sealed.
"""

import uuid

from enclavize.aws import ec2, signin


def lock(ec2_client, signin_client, *, res, account_id: str, region: str) -> tuple:
    vpc_id = ec2.create_anchor_vpc(
        ec2_client, cidr=res.signin_lock_vpc_cidr, tag=res.signin_lock_vpc_tag
    )
    statement_id = signin.enable_lock(
        signin_client,
        vpc_id=vpc_id,
        account_id=account_id,
        region=region,
        excluded_principal=res.console_user_arn(account_id),
        client_token=str(uuid.uuid4()),
    )
    return vpc_id, statement_id
