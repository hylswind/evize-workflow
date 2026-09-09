"""Instances, the anchor VPC, and region enumeration.

The launch retry here is the one piece of eventual-consistency handling proven
in production by the previous version: an instance profile created moments
earlier is not yet visible to RunInstances, and the call fails in a way that
looks like a bad argument.
"""

import time

from botocore.exceptions import ClientError

# RunInstances reports a not-yet-propagated instance profile as an argument
# error, so the message has to be inspected to avoid retrying genuine mistakes.
_PROFILE_ERROR_CODES = ("InvalidParameterValue", "InvalidIamInstanceProfile")
_PROFILE_ERROR_TEXT = "Instance Profile"


def resolve_ami(ssm_client, param: str) -> str:
    """The current Amazon Linux 2023 image id, from the public SSM parameter."""
    return ssm_client.get_parameter(Name=param)["Parameter"]["Value"]


def default_vpc(ec2) -> str:
    """The account is brand new, so the default VPC is all there is."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
    if not vpcs:
        raise RuntimeError("enclavize: this account has no default VPC to launch into")
    return vpcs[0]["VpcId"]


def default_subnets(ec2, vpc_id: str) -> list:
    """Every default-for-AZ subnet in the VPC, ordered by AZ.

    All of them rather than one: a load balancer has to span at least two
    Availability Zones, and the ordering keeps repeat runs comparable.
    """
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "default-for-az", "Values": ["true"]},
        ]
    )["Subnets"]
    if not subnets:
        raise RuntimeError("enclavize: the default VPC has no default subnet")
    return [s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZone"])]


def default_subnet(ec2) -> str:
    """A subnet in the default VPC, chosen deterministically: the lowest AZ."""
    return default_subnets(ec2, default_vpc(ec2))[0]


def create_security_group(ec2, *, name: str, description: str, vpc_id: str) -> str:
    """A group tagged with its own name, which is how a teardown finds it."""
    return ec2.create_security_group(
        GroupName=name,
        Description=description,
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["GroupId"]


def authorize_ingress(ec2, *, group_id: str, port: int, cidr: str = None,
                      source_group_id: str = None) -> None:
    """One inbound TCP rule: from anywhere, or from one other group.

    From a group rather than an address range is what lets the instance group
    admit the load balancer and nothing else — the balancer's addresses are not
    fixed, but its group is.
    """
    permission = {"IpProtocol": "tcp", "FromPort": port, "ToPort": port}
    if source_group_id:
        permission["UserIdGroupPairs"] = [{"GroupId": source_group_id}]
    else:
        permission["IpRanges"] = [{"CidrIp": cidr or "0.0.0.0/0"}]
    ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[permission])


def security_groups_named(ec2, prefix: str) -> list:
    """Groups whose name carries the prefix, as (id, name) pairs."""
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [f"{prefix}*"]}]
    )["SecurityGroups"]
    return [(g["GroupId"], g["GroupName"]) for g in groups]


def delete_security_group(ec2, group_id: str) -> None:
    ec2.delete_security_group(GroupId=group_id)


def launch(
    ec2,
    *,
    image_id: str,
    subnet_id: str,
    instance_profile: str,
    user_data: str,
    instance_type: str,
    name_tag: str,
    wait_seconds: int,
    retry_interval: int,
    sleep=time.sleep,
    now=time.monotonic,
) -> str:
    """Run one instance, retrying while the instance profile propagates."""
    deadline = now() + wait_seconds
    while True:
        try:
            response = ec2.run_instances(
                ImageId=image_id,
                InstanceType=instance_type,
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                UserData=user_data,
                IamInstanceProfile={"Name": instance_profile},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
            )
            return response["Instances"][0]["InstanceId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            propagating = code in _PROFILE_ERROR_CODES and _PROFILE_ERROR_TEXT in str(exc)
            if propagating and now() < deadline:
                sleep(retry_interval)
                continue
            raise


def terminate(ec2, instance_id: str) -> None:
    ec2.terminate_instances(InstanceIds=[instance_id])


def create_anchor_vpc(ec2, *, cidr: str, tag: str) -> str:
    """An empty VPC that exists only to be named in the sign-in policy.

    Console access is denied unless it originates from this VPC, and nothing can
    ever originate from it — it has no instances, no gateway, no way in. A fresh
    one is created every time: reusing a tagged VPC would silently accept an
    account someone had already sealed.
    """
    vpc_id = ec2.create_vpc(CidrBlock=cidr)["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": tag}])
    return vpc_id


def delete_vpc(ec2, vpc_id: str) -> None:
    ec2.delete_vpc(VpcId=vpc_id)


def enabled_regions(ec2) -> list:
    """Every region this account can act in.

    The event check has to sweep all of them: lookup_events is per-region, so a
    write made anywhere else would otherwise be invisible.
    """
    response = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    )
    return sorted(region["RegionName"] for region in response["Regions"])
