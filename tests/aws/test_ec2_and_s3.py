"""enclavize/aws/ec2.py and s3.py against real AWS.

The two questions worth real money here:

- does the instance-profile propagation retry actually fire, and is 90 seconds
  enough? Offline this is simulated; only a real account says whether the
  window is right.
- what does HeadBucket really return for a bucket that does not exist versus
  one owned by somebody else? The proof handover waits on the first and must
  fail immediately on the second.
"""

import time

import pytest
from botocore.exceptions import ClientError

from enclavize.aws import ec2 as ec2mod
from enclavize.aws import iam as iammod
from enclavize.aws import s3 as s3mod
from enclavize.logic import naming, policies, userdata
from workflow import config as workflow_config

pytestmark = pytest.mark.aws


@pytest.fixture
def launched(ec2):
    instances = []
    yield instances
    for instance_id in instances:
        try:
            ec2mod.terminate(ec2, instance_id)
        except ClientError:
            pass


@pytest.fixture
def buckets(s3):
    made = []
    yield made
    for bucket in made:
        try:
            s3mod.delete_bucket(s3, bucket)
        except ClientError:
            pass


# --- EC2 ------------------------------------------------------------------


def test_the_al2023_parameter_resolves_to_an_image(ssm, ec2):
    image_id = ec2mod.resolve_ami(ssm, workflow_config.BASE_AMI_PARAM)
    assert image_id.startswith("ami-")
    assert ec2.describe_images(ImageIds=[image_id])["Images"]


def test_the_account_has_a_default_subnet_to_launch_into(ec2):
    # A brand-new account has only the default VPC; if this is missing the
    # sealing run cannot launch at all.
    subnet_id = ec2mod.default_subnet(ec2)
    subnet = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    assert subnet["DefaultForAz"] is True


def test_launching_survives_instance_profile_propagation(ec2, ssm, iam, resources, launched):
    """The whole point of the retry: a profile made seconds ago is not yet
    visible to RunInstances, and the error looks like a bad argument."""
    iammod.create_role(iam, name=resources.admin_role, trust=policies.EC2_TRUST)
    iammod.create_instance_profile(iam, name=resources.instance_profile(), role=resources.admin_role)
    try:
        started = time.monotonic()
        instance_id = ec2mod.launch(
            ec2,
            image_id=ec2mod.resolve_ami(ssm, workflow_config.BASE_AMI_PARAM),
            subnet_id=ec2mod.default_subnet(ec2),
            instance_profile=resources.instance_profile(),
            user_data="#!/bin/bash\ntrue\n",
            instance_type=workflow_config.INSTANCE_TYPE,
            name_tag=resources.instance_name_tag,
            wait_seconds=workflow_config.INSTANCE_PROFILE_WAIT_SECONDS,
            retry_interval=workflow_config.INSTANCE_PROFILE_RETRY_INTERVAL,
        )
        launched.append(instance_id)
        waited = time.monotonic() - started
        # Recorded so the configured window can be judged against reality.
        print(f"launch took {waited:.1f}s of a {workflow_config.INSTANCE_PROFILE_WAIT_SECONDS}s budget")
        assert instance_id.startswith("i-")
        assert waited < workflow_config.INSTANCE_PROFILE_WAIT_SECONDS
    finally:
        iammod.delete_instance_profile(iam, name=resources.instance_profile())
        iammod.delete_role(iam, role=resources.admin_role)


def test_the_real_setup_userdata_is_accepted(ec2, ssm, iam, resources, launched):
    """User-data has a size limit and must be valid; this is the actual script."""
    iammod.create_role(iam, name=resources.admin_role, trust=policies.EC2_TRUST)
    iammod.create_instance_profile(iam, name=resources.instance_profile(), role=resources.admin_role)
    try:
        script = userdata.build_setup_userdata(
            self_repo="acme/enclavize-workflow", self_sha="a" * 40, region="us-east-1",
            domain="example.com", app_repo="acme/app", apply_api_key="k" * 32,
            go_param=resources.go_param,
        )
        instance_id = ec2mod.launch(
            ec2,
            image_id=ec2mod.resolve_ami(ssm, workflow_config.BASE_AMI_PARAM),
            subnet_id=ec2mod.default_subnet(ec2),
            instance_profile=resources.instance_profile(),
            user_data=script,
            instance_type=workflow_config.INSTANCE_TYPE,
            name_tag=resources.instance_name_tag,
            wait_seconds=workflow_config.INSTANCE_PROFILE_WAIT_SECONDS,
            retry_interval=workflow_config.INSTANCE_PROFILE_RETRY_INTERVAL,
        )
        launched.append(instance_id)
    finally:
        iammod.delete_instance_profile(iam, name=resources.instance_profile())
        iammod.delete_role(iam, role=resources.admin_role)


def test_the_anchor_vpc_can_be_created_and_removed(ec2, resources):
    vpc_id = ec2mod.create_anchor_vpc(
        ec2, cidr=resources.signin_lock_vpc_cidr, tag=resources.signin_lock_vpc_tag
    )
    try:
        vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        assert vpc["CidrBlock"] == resources.signin_lock_vpc_cidr
    finally:
        ec2mod.delete_vpc(ec2, vpc_id)


def test_every_enabled_region_is_listed(ec2):
    """The event check sweeps these; a short list means blind spots."""
    regions = ec2mod.enabled_regions(ec2)
    assert "us-east-1" in regions
    # A standard account has far more than a handful enabled by default.
    assert len(regions) >= 10
    print(f"{len(regions)} enabled regions to sweep")


# --- S3 -------------------------------------------------------------------


def test_a_bucket_is_created_private_and_versioned(s3, account_id, prefix, buckets):
    bucket = f"{prefix}{naming.proof_bucket_name(account_id)}"[:63]
    s3mod.create_bucket(s3, bucket, region="us-east-1")
    buckets.append(bucket)

    assert s3.get_bucket_versioning(Bucket=bucket)["Status"] == "Enabled"
    block = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    assert block["BlockPublicAcls"] is True
    # Left open so CloudFront can be granted read through a bucket policy.
    assert block["BlockPublicPolicy"] is False


def test_head_bucket_says_absent_rather_than_failing(s3, prefix):
    """The proof handover waits on this answer, so it must not raise."""
    assert s3mod.bucket_exists(s3, f"{prefix}definitely-not-created") is False


def test_a_bucket_owned_by_someone_else_stops_the_wait(s3):
    """403, not 404 — waiting could never succeed, so it has to fail loudly."""
    with pytest.raises(RuntimeError, match="not ours"):
        # A name that certainly exists and certainly is not ours.
        s3mod.bucket_exists(s3, "aws")


def test_proof_objects_round_trip(s3, account_id, prefix, buckets, tmp_path):
    bucket = f"{prefix}proof-{account_id}"[:63]
    s3mod.create_bucket(s3, bucket, region="us-east-1")
    buckets.append(bucket)
    statement = tmp_path / "statement.json"
    statement.write_text('{"accountID":"x"}', encoding="utf-8")

    s3mod.put_file(s3, bucket=bucket, key="statement.json", path=statement)

    assert s3mod.object_exists(s3, bucket=bucket, key="statement.json")
    assert s3mod.get_bytes(s3, bucket=bucket, key="statement.json") == statement.read_bytes()
