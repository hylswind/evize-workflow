"""The deploy interface: the only way anything new runs in this account.

An API key opens a REST endpoint that starts an Express state machine, which
launches one instance to clone an application commit and run it. The instance
carries a role capped by a permission boundary, so a deploy can build whatever
it likes and still cannot touch the enclave: not the identities, not the sign-in
lock, not the domain, not the proof, and not this machinery.

The boundary also propagates — a deploy may only create principals that carry it
— so the fence does not end at the first role a deploy makes for itself.
"""

import json

from enclavize.aws import apigw, ec2, iam, sfn
from enclavize.logic import policies, statemachine

from . import config


def boundary_document(*, res, account_id: str, region: str, proof_bucket: str,
                      dashboard_bucket: str, domain: str, hosted_zone_id: str, protected=None) -> dict:
    return policies.deploy_boundary_policy(
        account_id=account_id,
        region=region,
        resource_prefix=res.prefix,
        proof_bucket=proof_bucket,
        dashboard_bucket=dashboard_bucket,
        domain=domain,
        hosted_zone_id=hosted_zone_id,
        state_machine=res.deploy_state_machine,
        protected=protected,
    )


def tighten_boundary(iam_client, *, res, account_id: str, region: str, proof_bucket: str,
                     dashboard_bucket: str, domain: str, hosted_zone_id: str, protected: dict) -> None:
    """Narrow the machinery denial now that the real resources exist.

    Created service-wide and narrowed here rather than the other way round: the
    intermediate state is the stricter one, and nothing can deploy until setup
    has finished anyway.
    """
    iam.set_policy_document(
        iam_client,
        policy_arn=res.deploy_boundary_arn(account_id),
        document=boundary_document(
            res=res, account_id=account_id, region=region, proof_bucket=proof_bucket,
            dashboard_bucket=dashboard_bucket, domain=domain, hosted_zone_id=hosted_zone_id,
            protected=protected,
        ),
    )


def create_roles(iam_client, *, res, account_id: str, region: str, proof_bucket: str,
                 dashboard_bucket: str, domain: str, hosted_zone_id: str) -> dict:
    """The boundary, the deploy instance role, and the two service roles."""
    boundary_arn = iam.create_policy(
        iam_client,
        name=res.deploy_boundary,
        document=boundary_document(
            res=res, account_id=account_id, region=region, proof_bucket=proof_bucket,
            dashboard_bucket=dashboard_bucket, domain=domain, hosted_zone_id=hosted_zone_id,
        ),
        description="enclavize: the ceiling for everything a deploy creates",
    )

    # The boundary is attached to the role itself, so even this role cannot
    # exceed it.
    iam.create_role(
        iam_client,
        name=res.deploy_role,
        trust=policies.EC2_TRUST,
        description="enclavize: an instance deploying an application commit",
        boundary_arn=boundary_arn,
    )
    # Admin as the grant, the boundary as the ceiling. The role asks for
    # everything and receives everything the boundary permits.
    iam.attach_role_policy(iam_client, role=res.deploy_role, policy_arn=policies.ADMIN_MANAGED_POLICY)
    iam.put_role_policy(
        iam_client, role=res.deploy_role, name="keep-the-boundary",
        document=policies.deploy_role_policy(boundary_arn=boundary_arn),
    )
    iam.create_instance_profile(iam_client, name=res.deploy_role, role=res.deploy_role)

    sfn_role_arn = iam.create_role(
        iam_client,
        name=res.deploy_sfn_role,
        trust=policies.service_trust("states.amazonaws.com"),
        description="enclavize: the deploy state machine",
    )
    iam.put_role_policy(
        iam_client, role=res.deploy_sfn_role, name="launch-and-record",
        document={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ec2:RunInstances", "ec2:CreateTags", "ec2:DescribeInstances"],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{dashboard_bucket}/deploys/*",
                },
            ],
        },
    )
    # Passing any other role — the admin one above all — would step around the
    # boundary entirely.
    iam.put_role_policy(
        iam_client, role=res.deploy_sfn_role, name="pass-only-the-deploy-role",
        document=policies.pass_role_policy(account_id=account_id, role_name=res.deploy_role),
    )

    api_role_arn = iam.create_role(
        iam_client,
        name=res.deploy_api_role,
        trust=policies.service_trust("apigateway.amazonaws.com"),
        description="enclavize: the deploy API invoking the state machine",
    )
    return {
        "boundary_arn": boundary_arn,
        "sfn_role_arn": sfn_role_arn,
        "api_role_arn": api_role_arn,
    }


def create_state_machine(sfn_client, ec2_client, ssm_client, *, res, app_repo: str, region: str,
                         domain: str, dashboard_bucket: str, role_arn: str, ami_param: str,
                         instance_type: str) -> str:
    definition = statemachine.build_definition(
        app_repo=app_repo,
        region=region,
        domain=domain,
        image_id=ec2.resolve_ami(ssm_client, ami_param),
        instance_type=instance_type,
        subnet_id=ec2.default_subnet(ec2_client),
        instance_profile=res.deploy_role,
        dashboard_bucket=dashboard_bucket,
        name_tag=res.deploy_state_machine,
    )
    return sfn.create_state_machine(
        sfn_client, name=res.deploy_state_machine, definition=definition, role_arn=role_arn
    )


def create_api(apigw_client, iam_client, *, res, region: str, api_key: str, state_machine_arn: str,
               api_role_arn: str, account_id: str) -> str:
    """The REST API, its key, and the validator that guards the commit.

    A REST API rather than an HTTP one because only REST supports API keys.
    """
    iam.put_role_policy(
        iam_client, role=res.deploy_api_role, name="start-the-deploy",
        document={
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "states:StartSyncExecution", "Resource": state_machine_arn}
            ],
        },
    )

    api_id = apigw.create_api(apigw_client, name=res.deploy_api_name, description="enclavize deploy")
    root = apigw.root_resource_id(apigw_client, api_id)
    resource_id = apigw.create_resource(
        apigw_client, api_id=api_id, parent_id=root, path_part=config.DEPLOY_API_PATH
    )
    # The commit ends up in a shell command on the deploy instance, so it is
    # rejected at the edge unless it is exactly a 40-hex sha.
    model = apigw.create_commit_model(
        apigw_client, api_id=api_id, name="DeployRequest", pattern=config.COMMIT_PATTERN
    )
    validator_id = apigw.create_body_validator(apigw_client, api_id=api_id, name="body")
    apigw.put_key_protected_method(
        apigw_client, api_id=api_id, resource_id=resource_id, http_method="POST",
        model_name=model, validator_id=validator_id,
    )
    apigw.put_state_machine_integration(
        apigw_client, api_id=api_id, resource_id=resource_id, http_method="POST",
        region=region, credentials_arn=api_role_arn, state_machine_arn=state_machine_arn,
    )
    apigw.deploy(apigw_client, api_id=api_id, stage=config.DEPLOY_STAGE)

    key_id = apigw.create_api_key(apigw_client, name=res.deploy_api_name, value=api_key)
    apigw.attach_key_to_plan(
        apigw_client, name=f"{res.deploy_api_name}-plan", api_id=api_id,
        stage=config.DEPLOY_STAGE, key_id=key_id,
    )
    url = apigw.invoke_url(
        api_id=api_id, region=region, stage=config.DEPLOY_STAGE, path=config.DEPLOY_API_PATH
    )
    # The id is needed to name this API in the boundary once it exists.
    return url, api_id
