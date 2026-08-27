"""enclavize/aws/iam.py against moto.

Three of these cover logic that runs late in a bring-up, when nothing is
watching and a failure is silent: rotating the boundary's document, and the
detach-before-delete ordering IAM insists on.
"""

import boto3
import pytest
from botocore.exceptions import ClientError
from constants import ACCOUNT_ID, REGION
from moto import mock_aws

from enclavize.aws import iam as iammod
from enclavize.logic import policies


@pytest.fixture
def iam():
    with mock_aws():
        yield boto3.client("iam", region_name=REGION)


def a_policy(n=1):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": f"s3:Get{n}", "Resource": "*"}],
    }


def default_document(iam, arn):
    version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
    return iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]


# --- rotating the boundary's document -------------------------------------


def test_a_new_document_becomes_the_default(iam):
    """This is how the boundary is narrowed once the real ARNs exist."""
    arn = iammod.create_policy(iam, name="enclavize-apply-boundary", document=a_policy(1))

    iammod.set_policy_document(iam, policy_arn=arn, document=a_policy(2))

    assert default_document(iam, arn)["Statement"][0]["Action"] == "s3:Get2"


def test_the_oldest_version_is_dropped_at_the_five_version_cap(iam):
    """IAM allows five versions and then refuses. Without pruning, a re-run of
    the bring-up would fail here — late, and with the boundary left in its
    wider form."""
    arn = iammod.create_policy(iam, name="enclavize-apply-boundary", document=a_policy(0))

    for n in range(1, 8):
        iammod.set_policy_document(iam, policy_arn=arn, document=a_policy(n))

    versions = iam.list_policy_versions(PolicyArn=arn)["Versions"]
    assert len(versions) <= 5
    # The newest is still the one in force.
    assert default_document(iam, arn)["Statement"][0]["Action"] == "s3:Get7"


def test_the_default_version_is_never_the_one_pruned(iam):
    arn = iammod.create_policy(iam, name="enclavize-apply-boundary", document=a_policy(0))
    for n in range(1, 8):
        iammod.set_policy_document(iam, policy_arn=arn, document=a_policy(n))

    versions = iam.list_policy_versions(PolicyArn=arn)["Versions"]
    assert sum(1 for v in versions if v["IsDefaultVersion"]) == 1


def test_the_real_boundary_document_can_be_rotated(iam):
    """The service-wide form is created first and narrowed in place."""
    wide = policies.apply_boundary_policy(
        account_id=ACCOUNT_ID, region=REGION, resource_prefix="enclavize-",
        proof_bucket="p", dashboard_bucket="d", domain="example.com",
        hosted_zone_id="Z1", state_machine="enclavize-apply",
    )
    narrow = policies.apply_boundary_policy(
        account_id=ACCOUNT_ID, region=REGION, resource_prefix="enclavize-",
        proof_bucket="p", dashboard_bucket="d", domain="example.com",
        hosted_zone_id="Z1", state_machine="enclavize-apply",
        protected={"api_id": "abc", "distribution_ids": ["E1"]},
    )
    arn = iammod.create_policy(iam, name="enclavize-apply-boundary", document=wide)

    iammod.set_policy_document(iam, policy_arn=arn, document=narrow)

    machinery = [s for s in default_document(iam, arn)["Statement"]
                 if s.get("Sid") == "CannotRewriteTheApplyMachinery"][0]
    assert machinery["Resource"] != "*"


# --- detach before delete -------------------------------------------------


def test_a_role_is_stripped_before_it_is_deleted(iam):
    """IAM refuses to delete a role that still has policies attached."""
    iammod.create_role(iam, name="enclavize-apply", trust=policies.EC2_TRUST)
    iammod.attach_role_policy(iam, role="enclavize-apply", policy_arn=policies.ADMIN_MANAGED_POLICY)
    iammod.put_role_policy(iam, role="enclavize-apply", name="inline", document=a_policy())

    iammod.delete_role(iam, role="enclavize-apply")

    with pytest.raises(ClientError) as exc:
        iam.get_role(RoleName="enclavize-apply")
    assert exc.value.response["Error"]["Code"] == "NoSuchEntity"


def test_a_policy_is_detached_from_everything_before_it_is_deleted(iam):
    """A boundary is attached to every principal an applied commit made, so deleting it
    means finding them all first."""
    arn = iammod.create_policy(iam, name="enclavize-apply-boundary", document=a_policy())
    iammod.create_role(iam, name="enclavize-apply", trust=policies.EC2_TRUST)
    iam.attach_role_policy(RoleName="enclavize-apply", PolicyArn=arn)
    iammod.create_user(iam, name="enclavize-someone")
    iam.attach_user_policy(UserName="enclavize-someone", PolicyArn=arn)

    iammod.delete_policy(iam, policy_arn=arn)

    with pytest.raises(ClientError) as exc:
        iam.get_policy(PolicyArn=arn)
    assert exc.value.response["Error"]["Code"] == "NoSuchEntity"


def test_extra_versions_are_removed_before_the_policy_is(iam):
    # IAM will not delete a policy that still has non-default versions.
    arn = iammod.create_policy(iam, name="enclavize-apply-boundary", document=a_policy(1))
    iammod.set_policy_document(iam, policy_arn=arn, document=a_policy(2))
    iammod.set_policy_document(iam, policy_arn=arn, document=a_policy(3))

    iammod.delete_policy(iam, policy_arn=arn)

    with pytest.raises(ClientError):
        iam.get_policy(PolicyArn=arn)


def test_a_user_is_stripped_of_everything_that_would_block_deletion(iam):
    """The starter user is retired this way once proof has landed."""
    iammod.create_user(iam, name="enclavize-starter")
    iammod.create_access_key(iam, user="enclavize-starter")
    iammod.put_user_policy(iam, user="enclavize-starter", name="inline", document=a_policy())
    iammod.attach_user_policy(iam, user="enclavize-starter", policy_arn=policies.VIEW_ONLY_MANAGED_POLICY)
    iammod.create_login_profile(iam, user="enclavize-starter",
                                password=iammod.generate_password(), reset_required=False)

    iammod.delete_user(iam, user="enclavize-starter")

    with pytest.raises(ClientError) as exc:
        iam.get_user(UserName="enclavize-starter")
    assert exc.value.response["Error"]["Code"] == "NoSuchEntity"


def test_deleting_a_user_without_a_login_profile_is_not_an_error(iam):
    # The reader and starter never get one; only the console user does.
    iammod.create_user(iam, name="enclavize-event-reader")
    iammod.delete_user(iam, user="enclavize-event-reader")


# --- the generated console password ---------------------------------------


def test_the_generated_password_covers_every_character_class():
    for _ in range(20):
        password = iammod.generate_password()
        assert len(password) == 32
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(c in "!@#$%^&*()-_=+" for c in password)


def test_two_passwords_are_never_the_same():
    assert len({iammod.generate_password() for _ in range(50)}) == 50
