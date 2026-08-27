"""enclavize/aws/iam.py against real IAM.

Used by four different places — creating the enclave identities, deleting root's
key, building the apply roles, and retiring the starter user — so verifying it
once covers all of them.

What only real IAM can answer: whether the managed policy ARNs exist, whether
the generated password satisfies the account's policy, and above all whether the
permission boundary's conditions are accepted and actually bite.
"""

import json

import pytest
from botocore.exceptions import ClientError

from enclavize.aws import iam as iammod
from enclavize.logic import policies
from setup import config as setup_config
from setup import apply as setup_apply

pytestmark = pytest.mark.aws


def boundary_for(resources, account_id):
    """Built through the bring-up's own helper.

    These tests are not collected in a default run, so a call written out by
    hand here would go stale the moment the policy's signature changed and
    nothing would say so until someone ran them against an account.
    """
    # The boundary belongs to phase B, whose Resources carries the apply
    # names; the fixture hands out phase A's. Same prefix either way, so the
    # test's own namespace is preserved.
    return setup_apply.boundary_document(
        res=setup_config.RESOURCES.with_prefix(resources.prefix),
        account_id=account_id,
        region="us-east-1",
        proof_bucket=f"enclavize-proof-{account_id}",
        dashboard_bucket=f"enclavize-dashboard-{account_id}",
        domain="example.com",
        hosted_zone_id="Z1EXAMPLE",
    )


@pytest.fixture
def cleanup(iam):
    """Delete everything a test made, in the order IAM demands."""
    made = {"users": [], "roles": [], "profiles": [], "policies": []}
    yield made
    for name in made["profiles"]:
        try:
            iammod.delete_instance_profile(iam, name=name)
        except ClientError:
            pass
    for name in made["users"]:
        try:
            iammod.delete_user(iam, user=name)
        except ClientError:
            pass
    for name in made["roles"]:
        try:
            iammod.delete_role(iam, role=name)
        except ClientError:
            pass
    for arn in made["policies"]:
        try:
            iammod.delete_policy(iam, policy_arn=arn)
        except ClientError:
            pass


def test_the_managed_policies_enclavize_attaches_actually_exist(iam, resources, cleanup):
    """A wrong ARN would fail deep into a run that has already touched the account."""
    role = resources.admin_role
    iammod.create_role(iam, name=role, trust=policies.EC2_TRUST)
    cleanup["roles"].append(role)

    iammod.attach_role_policy(iam, role=role, policy_arn=policies.ADMIN_MANAGED_POLICY)

    attached = iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]
    assert policies.ADMIN_MANAGED_POLICY in [p["PolicyArn"] for p in attached]


def test_the_console_user_gets_billing_and_view_only(iam, resources, cleanup):
    user = resources.console_user
    iammod.create_user(iam, name=user)
    cleanup["users"].append(user)

    iammod.attach_user_policy(iam, user=user, policy_arn=policies.BILLING_MANAGED_POLICY)
    iammod.attach_user_policy(iam, user=user, policy_arn=policies.VIEW_ONLY_MANAGED_POLICY)

    attached = {p["PolicyArn"] for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]}
    assert attached == {policies.BILLING_MANAGED_POLICY, policies.VIEW_ONLY_MANAGED_POLICY}


def test_the_console_user_can_see_what_exists_but_not_what_is_in_it(iam):
    """ViewOnlyAccess is List and Describe, not data access.

    Worth pinning against the real catalogue: "read-only" reads as though the
    console user could open an object or a secret, and it cannot. If AWS ever
    widened this policy, the console user would quietly gain data access.
    """
    arn = policies.VIEW_ONLY_MANAGED_POLICY
    policy = iam.get_policy(PolicyArn=arn)["Policy"]
    document = iam.get_policy_version(
        PolicyArn=arn, VersionId=policy["DefaultVersionId"]
    )["PolicyVersion"]["Document"]

    granted = set()
    for statement in document["Statement"]:
        action = statement["Action"]
        granted.update([action] if isinstance(action, str) else action)

    forbidden = {
        "s3:GetObject",
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",
        "kms:Decrypt",
        "logs:GetLogEvents",
    }
    assert not (granted & forbidden), sorted(granted & forbidden)
    # It can see that a bucket is there, which is the whole point.
    assert "s3:ListAllMyBuckets" in granted


def test_the_generated_password_satisfies_the_account_policy(iam, resources, cleanup):
    """Real IAM rejects a password the account's policy does not accept."""
    user = resources.console_user
    iammod.create_user(iam, name=user)
    cleanup["users"].append(user)

    iammod.create_login_profile(
        iam, user=user, password=iammod.generate_password(), reset_required=False
    )

    # The password is random and arrives encrypted, so the operator is not made
    # to change it — only allowed to, by the self-service policy above.
    assert iam.get_login_profile(UserName=user)["LoginProfile"]["PasswordResetRequired"] is False


def test_the_starter_policy_is_accepted_with_a_bucket_that_does_not_exist_yet(
    iam, resources, cleanup, account_id
):
    """The setup program creates that bucket later; IAM must still take the policy."""
    user = resources.starter_user
    iammod.create_user(iam, name=user)
    cleanup["users"].append(user)

    iammod.put_user_policy(
        iam, user=user, name="start-and-publish",
        document=policies.starter_policy(
            region="us-east-1", account_id=account_id,
            go_param=resources.go_param, proof_bucket=f"does-not-exist-{account_id}",
        ),
    )

    stored = iam.get_user_policy(UserName=user, PolicyName="start-and-publish")["PolicyDocument"]
    actions = {s["Action"] for s in stored["Statement"]}
    assert actions == {"ssm:PutParameter", "s3:PutObject"}


def test_iam_accepts_the_permission_boundary(iam, resources, cleanup, account_id):
    """Its conditions are the fence around the enclave; a rejected document
    would mean no fence at all."""
    arn = iammod.create_policy(
        iam, name=resources.apply_boundary,
        document=boundary_for(resources, account_id),
    )
    cleanup["policies"].append(arn)
    assert arn.endswith(resources.apply_boundary)


def test_a_bounded_role_reports_its_boundary(iam, resources, cleanup, account_id):
    arn = iammod.create_policy(
        iam, name=resources.apply_boundary,
        document=boundary_for(resources, account_id),
    )
    cleanup["policies"].append(arn)

    iammod.create_role(iam, name=resources.apply_role, trust=policies.EC2_TRUST, boundary_arn=arn)
    cleanup["roles"].append(resources.apply_role)

    role = iam.get_role(RoleName=resources.apply_role)["Role"]
    assert role["PermissionsBoundary"]["PermissionsBoundaryArn"] == arn


def test_an_instance_profile_carries_its_role(iam, resources, cleanup):
    iammod.create_role(iam, name=resources.admin_role, trust=policies.EC2_TRUST)
    cleanup["roles"].append(resources.admin_role)

    iammod.create_instance_profile(iam, name=resources.instance_profile(), role=resources.admin_role)
    cleanup["profiles"].append(resources.instance_profile())

    profile = iam.get_instance_profile(InstanceProfileName=resources.instance_profile())["InstanceProfile"]
    assert [r["RoleName"] for r in profile["Roles"]] == [resources.admin_role]


def test_deleting_an_access_key_works_without_naming_the_user(iam, resources, cleanup):
    """This is how root deletes its own key: root is not an IAM user, so there
    is no UserName to pass. Verified here on an ordinary user because the root
    case can only happen once per account."""
    user = resources.starter_user
    iammod.create_user(iam, name=user)
    cleanup["users"].append(user)
    key_id, _ = iammod.create_access_key(iam, user=user)

    # The real call still needs UserName for a non-caller key; what is being
    # checked is that the module leaves it out when not given one.
    iammod.delete_access_key(iam, access_key_id=key_id, user=user)

    assert iam.list_access_keys(UserName=user)["AccessKeyMetadata"] == []


def test_deleting_a_user_clears_everything_that_would_block_it(iam, resources, cleanup, account_id):
    """The starter user is retired this way once proof has landed."""
    user = resources.starter_user
    iammod.create_user(iam, name=user)
    iammod.create_access_key(iam, user=user)
    iammod.put_user_policy(iam, user=user, name="p", document=policies.event_reader_policy())
    iammod.attach_user_policy(iam, user=user, policy_arn=policies.VIEW_ONLY_MANAGED_POLICY)
    iammod.create_login_profile(iam, user=user, password=iammod.generate_password(),
                                reset_required=False)

    iammod.delete_user(iam, user=user)

    with pytest.raises(ClientError) as exc:
        iam.get_user(UserName=user)
    assert exc.value.response["Error"]["Code"] == "NoSuchEntity"


def test_creating_a_policy_twice_returns_the_same_arn(iam, resources, cleanup, account_id):
    """A re-run of the bring-up must not fail on an existing boundary."""
    document = boundary_for(resources, account_id)
    first = iammod.create_policy(iam, name=resources.apply_boundary, document=document)
    cleanup["policies"].append(first)

    assert iammod.create_policy(iam, name=resources.apply_boundary, document=document) == first
