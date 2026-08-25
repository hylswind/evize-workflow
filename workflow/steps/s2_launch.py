"""Launch the instance that will bring the account up.

It boots while the account is still being sealed and blocks in its user-data
until the go flag appears, so nothing it does can precede the seal. Launching
happens last among the root-credentialed steps because it needs root, and the
step right after this deletes root's key.
"""

from enclavize.aws import ec2


def launch(ec2_client, ssm_client, *, res, user_data: str, ami_param: str, instance_type: str,
           wait_seconds: int, retry_interval: int) -> str:
    image_id = ec2.resolve_ami(ssm_client, ami_param)
    subnet_id = ec2.default_subnet(ec2_client)
    return ec2.launch(
        ec2_client,
        image_id=image_id,
        subnet_id=subnet_id,
        instance_profile=res.instance_profile(),
        user_data=user_data,
        instance_type=instance_type,
        name_tag=res.instance_name_tag,
        wait_seconds=wait_seconds,
        retry_interval=retry_interval,
    )
