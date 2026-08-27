"""Create the identities that outlive the root key.

Four principals, each as narrow as its job allows:
- admin role, assumable only by EC2, for the instance that brings the account up
- event reader, to audit the sealing after the fact
- starter, to fire the go flag and publish proof once root is gone
- console user, so a human can still see billing without being able to act

The starter's proof permission names a bucket the setup program has not created
yet, which IAM allows: a policy may reference an ARN before it exists.
"""

from enclavize.aws import iam
from enclavize.logic import naming, policies


def create_identities(iam_client, *, res, region: str, account_id: str) -> dict:
    """Create everything and return the credentials the run will need later."""
    proof_bucket = naming.proof_bucket_name(account_id)

    iam.create_role(
        iam_client,
        name=res.admin_role,
        trust=policies.EC2_TRUST,
        description="enclavize: the instance that brings the sealed account up",
    )
    iam.attach_role_policy(iam_client, role=res.admin_role, policy_arn=policies.ADMIN_MANAGED_POLICY)
    iam.create_instance_profile(iam_client, name=res.instance_profile(), role=res.admin_role)

    iam.create_user(iam_client, name=res.event_reader_user)
    iam.put_user_policy(
        iam_client, user=res.event_reader_user, name="read-events",
        document=policies.event_reader_policy(),
    )
    reader_key, reader_secret = iam.create_access_key(iam_client, user=res.event_reader_user)

    iam.create_user(iam_client, name=res.starter_user)
    iam.put_user_policy(
        iam_client, user=res.starter_user, name="start-and-publish",
        document=policies.starter_policy(
            region=region, account_id=account_id, go_param=res.go_param, proof_bucket=proof_bucket
        ),
    )
    starter_key, starter_secret = iam.create_access_key(iam_client, user=res.starter_user)

    console_password = iam.generate_password()
    iam.create_user(iam_client, name=res.console_user)
    iam.attach_user_policy(iam_client, user=res.console_user, policy_arn=policies.BILLING_MANAGED_POLICY)
    iam.attach_user_policy(iam_client, user=res.console_user, policy_arn=policies.VIEW_ONLY_MANAGED_POLICY)
    iam.put_user_policy(
        iam_client, user=res.console_user, name="change-own-password",
        document=policies.console_self_service_policy(account_id=account_id),
    )
    # No access key for this one: it is a pair of eyes, not a way to act.
    #
    # Not forced to change the password, though the policy above lets it. The
    # generated password is already random and reaches the operator inside an
    # encrypted archive; demanding a new one buys nothing and costs a prompt in
    # front of the only view anyone has of a sealed account.
    iam.create_login_profile(
        iam_client, user=res.console_user, password=console_password, reset_required=False
    )

    return {
        "instance_profile": res.instance_profile(),
        "reader_key": reader_key,
        "reader_secret": reader_secret,
        "starter_key": starter_key,
        "starter_secret": starter_secret,
        "console_password": console_password,
        "proof_bucket": proof_bucket,
    }
