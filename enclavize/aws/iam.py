"""Identities: the ones enclavize leaves behind, and the ones an apply may mint.

Used by both phases — phase A creates the enclave identities and deletes the
root key, phase B creates the apply role and later deletes the starter user.
All names arrive as arguments so a test can work under its own prefix.
"""

import json
import secrets
import string

from botocore.exceptions import ClientError

_PASSWORD_ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()-_=+"


def generate_password(length: int = 32) -> str:
    """A console password meeting the default AWS complexity requirements.

    Regenerates rather than patching so the result stays uniformly random.
    """
    classes = (string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()-_=+")
    while True:
        candidate = "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))
        if all(any(c in group for c in candidate) for group in classes):
            return candidate


def create_role(iam, *, name: str, trust: dict, description: str = "", boundary_arn: str = None) -> str:
    kwargs = {
        "RoleName": name,
        "AssumeRolePolicyDocument": json.dumps(trust),
        "Description": description,
    }
    if boundary_arn:
        kwargs["PermissionsBoundary"] = boundary_arn
    return iam.create_role(**kwargs)["Role"]["Arn"]


def attach_role_policy(iam, *, role: str, policy_arn: str) -> None:
    iam.attach_role_policy(RoleName=role, PolicyArn=policy_arn)


def put_role_policy(iam, *, role: str, name: str, document: dict) -> None:
    iam.put_role_policy(RoleName=role, PolicyName=name, PolicyDocument=json.dumps(document))


def create_instance_profile(iam, *, name: str, role: str) -> str:
    arn = iam.create_instance_profile(InstanceProfileName=name)["InstanceProfile"]["Arn"]
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=role)
    return arn


def create_user(iam, *, name: str, boundary_arn: str = None) -> str:
    kwargs = {"UserName": name}
    if boundary_arn:
        kwargs["PermissionsBoundary"] = boundary_arn
    return iam.create_user(**kwargs)["User"]["Arn"]


def put_user_policy(iam, *, user: str, name: str, document: dict) -> None:
    iam.put_user_policy(UserName=user, PolicyName=name, PolicyDocument=json.dumps(document))


def attach_user_policy(iam, *, user: str, policy_arn: str) -> None:
    iam.attach_user_policy(UserName=user, PolicyArn=policy_arn)


def create_access_key(iam, *, user: str) -> tuple:
    key = iam.create_access_key(UserName=user)["AccessKey"]
    return key["AccessKeyId"], key["SecretAccessKey"]


def create_login_profile(iam, *, user: str, password: str, reset_required: bool) -> None:
    """Give a user a console password.

    `reset_required` has no default: whether a human is made to change a
    password before they can do anything is a decision for the caller that
    hands it out, not a convention to inherit from here.
    """
    iam.create_login_profile(UserName=user, Password=password, PasswordResetRequired=reset_required)


def create_policy(iam, *, name: str, document: dict, description: str = "") -> str:
    """Create a customer-managed policy, returning its ARN.

    Used for the apply permission boundary, which has to be a standalone policy
    so it can be named in a PermissionsBoundary condition.
    """
    try:
        return iam.create_policy(
            PolicyName=name, PolicyDocument=json.dumps(document), Description=description
        )["Policy"]["Arn"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityAlreadyExists":
            raise
        return next(
            policy["Arn"]
            for page in iam.get_paginator("list_policies").paginate(Scope="Local")
            for policy in page["Policies"]
            if policy["PolicyName"] == name
        )


def set_policy_document(iam, *, policy_arn: str, document: dict) -> None:
    """Replace a managed policy's document with a new default version.

    IAM keeps at most five versions, so the oldest non-default is dropped first
    rather than letting the call fail on a limit.
    """
    versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    if len(versions) >= 5:
        oldest = min(
            (v for v in versions if not v["IsDefaultVersion"]),
            key=lambda v: v["CreateDate"],
        )
        iam.delete_policy_version(PolicyArn=policy_arn, VersionId=oldest["VersionId"])
    iam.create_policy_version(
        PolicyArn=policy_arn, PolicyDocument=json.dumps(document), SetAsDefault=True
    )


def delete_access_key(iam, *, access_key_id: str, user: str = None) -> None:
    """Delete an access key.

    UserName is omitted when root deletes its own key: the API infers the caller,
    and root is not an IAM user that could be named.
    """
    kwargs = {"AccessKeyId": access_key_id}
    if user:
        kwargs["UserName"] = user
    iam.delete_access_key(**kwargs)


def delete_user(iam, *, user: str) -> None:
    """Remove a user and everything that would block its deletion.

    Used to retire the starter identity once proof has landed, which is what
    makes the proof bucket unwritable from inside the account.
    """
    for page in iam.get_paginator("list_access_keys").paginate(UserName=user):
        for key in page["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
    for page in iam.get_paginator("list_user_policies").paginate(UserName=user):
        for name in page["PolicyNames"]:
            iam.delete_user_policy(UserName=user, PolicyName=name)
    for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=user):
        for policy in page["AttachedPolicies"]:
            iam.detach_user_policy(UserName=user, PolicyArn=policy["PolicyArn"])
    try:
        iam.delete_login_profile(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    iam.delete_user(UserName=user)


def delete_role(iam, *, role: str) -> None:
    for page in iam.get_paginator("list_role_policies").paginate(RoleName=role):
        for name in page["PolicyNames"]:
            iam.delete_role_policy(RoleName=role, PolicyName=name)
    for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role):
        for policy in page["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role, PolicyArn=policy["PolicyArn"])
    iam.delete_role(RoleName=role)


def delete_instance_profile(iam, *, name: str) -> None:
    profile = iam.get_instance_profile(InstanceProfileName=name)["InstanceProfile"]
    for role in profile["Roles"]:
        iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=role["RoleName"])
    iam.delete_instance_profile(InstanceProfileName=name)


def delete_policy(iam, *, policy_arn: str) -> None:
    for page in iam.get_paginator("list_entities_for_policy").paginate(PolicyArn=policy_arn):
        for role in page.get("PolicyRoles", []):
            iam.detach_role_policy(RoleName=role["RoleName"], PolicyArn=policy_arn)
        for user in page.get("PolicyUsers", []):
            iam.detach_user_policy(UserName=user["UserName"], PolicyArn=policy_arn)
    for version in iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]:
        if not version["IsDefaultVersion"]:
            iam.delete_policy_version(PolicyArn=policy_arn, VersionId=version["VersionId"])
    iam.delete_policy(PolicyArn=policy_arn)
