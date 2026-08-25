"""Launching, and the propagation retry that a real account taught the old version."""

import boto3
import pytest
from botocore.exceptions import ClientError
from constants import REGION, clock, no_sleep
from moto import mock_aws

from enclavize.aws import ec2 as ec2mod


@pytest.fixture
def ec2():
    with mock_aws():
        yield boto3.client("ec2", region_name=REGION)


def profile_error(code="InvalidParameterValue"):
    return ClientError(
        {"Error": {"Code": code, "Message": "Invalid IAM Instance Profile name"}}, "RunInstances"
    )


class Launcher:
    """Fails a set number of times before succeeding."""

    def __init__(self, failures, exc=None):
        self.failures = failures
        self.exc = exc or profile_error()
        self.attempts = 0

    def run_instances(self, **_kwargs):
        self.attempts += 1
        if self.attempts <= self.failures:
            raise self.exc
        return {"Instances": [{"InstanceId": "i-abc"}]}


def launch(client, **overrides):
    kwargs = dict(
        image_id="ami-1",
        subnet_id="subnet-1",
        instance_profile="enclavize-admin",
        user_data="#!/bin/bash\n",
        instance_type="t3.small",
        name_tag="enclavize-instance",
        wait_seconds=90,
        retry_interval=3,
        sleep=no_sleep,
        now=clock([0, 1, 2, 3, 4]),
    )
    kwargs.update(overrides)
    return ec2mod.launch(client, **kwargs)


def test_launch_retries_while_the_instance_profile_propagates():
    # A profile created moments earlier is not yet visible to RunInstances.
    client = Launcher(failures=2)
    assert launch(client) == "i-abc"
    assert client.attempts == 3


@pytest.mark.parametrize("code", ["InvalidParameterValue", "InvalidIamInstanceProfile"])
def test_both_propagation_error_codes_are_retried(code):
    client = Launcher(failures=1, exc=profile_error(code))
    assert launch(client) == "i-abc"


def test_an_unrelated_argument_error_is_not_retried():
    # Retrying a genuine mistake would burn the whole window before failing.
    exc = ClientError({"Error": {"Code": "InvalidParameterValue", "Message": "bad subnet"}}, "RunInstances")
    client = Launcher(failures=1, exc=exc)
    with pytest.raises(ClientError):
        launch(client)
    assert client.attempts == 1


def test_retrying_stops_at_the_deadline():
    client = Launcher(failures=99)
    with pytest.raises(ClientError):
        launch(client, now=clock([0, 1000]))


def test_launch_passes_userdata_and_tags(ec2):
    image_id = ec2.describe_images()["Images"][0]["ImageId"]
    subnet_id = ec2mod.default_subnet(ec2)
    recorded = {}

    class Recorder:
        def run_instances(self, **kwargs):
            recorded.update(kwargs)
            return {"Instances": [{"InstanceId": "i-1"}]}

    launch(Recorder(), image_id=image_id, subnet_id=subnet_id)

    assert recorded["UserData"] == "#!/bin/bash\n"
    assert recorded["IamInstanceProfile"] == {"Name": "enclavize-admin"}
    assert recorded["MinCount"] == 1 and recorded["MaxCount"] == 1
    tags = recorded["TagSpecifications"][0]
    assert tags["ResourceType"] == "instance"
    assert {"Key": "Name", "Value": "enclavize-instance"} in tags["Tags"]


def test_default_subnet_picks_the_lowest_availability_zone(ec2):
    subnet_id = ec2mod.default_subnet(ec2)
    subnet = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    all_default = ec2.describe_subnets(Filters=[{"Name": "default-for-az", "Values": ["true"]}])["Subnets"]
    assert subnet["AvailabilityZone"] == min(s["AvailabilityZone"] for s in all_default)


def test_anchor_vpc_is_tagged_so_it_can_be_recognised(ec2):
    vpc_id = ec2mod.create_anchor_vpc(ec2, cidr="10.255.0.0/28", tag="enclavize-signin-lock-vpc")
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    assert {"Key": "Name", "Value": "enclavize-signin-lock-vpc"} in vpc["Tags"]
    assert vpc["CidrBlock"] == "10.255.0.0/28"


def test_anchor_vpc_is_always_new(ec2):
    # Reusing a tagged VPC would silently accept an already-sealed account.
    first = ec2mod.create_anchor_vpc(ec2, cidr="10.255.0.0/28", tag="t")
    second = ec2mod.create_anchor_vpc(ec2, cidr="10.255.0.0/28", tag="t")
    assert first != second


def test_enabled_regions_are_sorted_and_include_the_home_region(ec2):
    regions = ec2mod.enabled_regions(ec2)
    assert regions == sorted(regions)
    assert REGION in regions
    assert len(regions) > 1


def test_resolve_ami_reads_the_public_parameter():
    class FakeSsm:
        def get_parameter(self, Name):
            assert Name == "/aws/service/ami-amazon-linux-latest/al2023-x86_64"
            return {"Parameter": {"Value": "ami-0123"}}

    assert ec2mod.resolve_ami(FakeSsm(), "/aws/service/ami-amazon-linux-latest/al2023-x86_64") == "ami-0123"
