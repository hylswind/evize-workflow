"""The apply interface: the only way anything new runs in this account.

Applying a commit, not deploying an application: what a commit's setup.sh does
is its own business. It may ship a new version of the application, or only
rearrange the account's resources, or both. The account is whatever the last
applied commit made it.

An API key opens a REST endpoint that starts an Express state machine, which
decides: refuse if an apply is already in flight; launch the commit at once,
in NEW mode, if nothing is serving yet; and otherwise launch the *serving*
commit once more, in UPDATE mode, to prepare for the one coming, and set a
timer. A Standard state machine, started by that timer every few minutes,
reads whether the preparer has said ready — or whether the wait is up — and
then launches the new commit and writes it down as serving.

Every instance carries a role capped by a permission boundary, so a commit can
build whatever it likes and still cannot touch the enclave: not the
identities, not the sign-in lock, not the domain, not the proof, not the
account's own bookkeeping of what is serving, and not this machinery.

The boundary also propagates — an applied commit may only create principals that
carry it — so the fence does not end at the first role a commit makes for
itself.
"""

import json

from enclavize.aws import apigw, dns, ec2, iam, sfn
from enclavize.logic import checkmachine, naming, policies, statemachine

from . import config


def check_state_machine_arn(*, res, region: str, account_id: str) -> str:
    """Known before the machine exists, which is what lets the receiving
    machine and the roles name it first."""
    return f"arn:aws:states:{region}:{account_id}:stateMachine:{res.apply_check_state_machine}"


def boundary_document(*, res, account_id: str, region: str, proof_bucket: str,
                      dashboard_bucket: str, domain: str, hosted_zone_id: str, protected=None) -> dict:
    return policies.apply_boundary_policy(
        account_id=account_id,
        region=region,
        resource_prefix=res.prefix,
        proof_bucket=proof_bucket,
        dashboard_bucket=dashboard_bucket,
        domain=domain,
        hosted_zone_id=hosted_zone_id,
        state_machine=res.apply_state_machine,
        check_state_machine=res.apply_check_state_machine,
        parameters=res.enclave_params(),
        protected=protected,
    )


def tighten_boundary(iam_client, *, res, account_id: str, region: str, proof_bucket: str,
                     dashboard_bucket: str, domain: str, hosted_zone_id: str, protected: dict) -> None:
    """Narrow the machinery denial now that the real resources exist.

    Created service-wide and narrowed here rather than the other way round: the
    intermediate state is the stricter one, and nothing can be applied until setup
    has finished anyway.
    """
    iam.set_policy_document(
        iam_client,
        policy_arn=res.apply_boundary_arn(account_id),
        document=boundary_document(
            res=res, account_id=account_id, region=region, proof_bucket=proof_bucket,
            dashboard_bucket=dashboard_bucket, domain=domain, hosted_zone_id=hosted_zone_id,
            protected=protected,
        ),
    )


def create_roles(iam_client, *, res, account_id: str, region: str, proof_bucket: str,
                 dashboard_bucket: str, domain: str, hosted_zone_id: str) -> dict:
    """The boundary, the apply instance role, and the three service roles."""
    boundary_arn = iam.create_policy(
        iam_client,
        name=res.apply_boundary,
        document=boundary_document(
            res=res, account_id=account_id, region=region, proof_bucket=proof_bucket,
            dashboard_bucket=dashboard_bucket, domain=domain, hosted_zone_id=hosted_zone_id,
        ),
        description="enclavize: the ceiling for everything an applied commit creates",
    )

    # The boundary is attached to the role itself, so even this role cannot
    # exceed it.
    iam.create_role(
        iam_client,
        name=res.apply_role,
        trust=policies.EC2_TRUST,
        description="enclavize: an instance applying a commit",
        boundary_arn=boundary_arn,
    )
    # Admin as the grant, the boundary as the ceiling. The role asks for
    # everything and receives everything the boundary permits.
    iam.attach_role_policy(iam_client, role=res.apply_role, policy_arn=policies.ADMIN_MANAGED_POLICY)
    iam.put_role_policy(
        iam_client, role=res.apply_role, name="keep-the-boundary",
        document=policies.apply_role_policy(boundary_arn=boundary_arn),
    )
    iam.create_instance_profile(iam_client, name=res.apply_role, role=res.apply_role)

    # One role for both workflows: the same service principal, and what they
    # may do overlaps almost entirely.
    sfn_role_arn = iam.create_role(
        iam_client,
        name=res.apply_sfn_role,
        trust=policies.service_trust("states.amazonaws.com"),
        description="enclavize: the apply workflows",
    )
    iam.put_role_policy(
        iam_client, role=res.apply_sfn_role, name="launch-check-and-record",
        document=policies.apply_state_machine_policy(
            region=region, account_id=account_id, dashboard_bucket=dashboard_bucket,
            check_state_machine=res.apply_check_state_machine,
            schedule=res.apply_check_schedule, scheduler_role=res.apply_scheduler_role,
            instance_name_tag=res.apply_state_machine,
            parameters=[res.apply_current_param, res.apply_pending_param, res.apply_ready_param],
        ),
    )
    # Passing any other role to an instance — the admin one above all — would
    # step around the boundary entirely.
    iam.put_role_policy(
        iam_client, role=res.apply_sfn_role, name="pass-only-the-apply-role",
        document=policies.pass_role_policy(account_id=account_id, role_name=res.apply_role),
    )

    scheduler_role_arn = iam.create_role(
        iam_client,
        name=res.apply_scheduler_role,
        trust=policies.scheduler_trust(account_id=account_id, region=region),
        description="enclavize: the timer that starts the check",
    )
    iam.put_role_policy(
        iam_client, role=res.apply_scheduler_role, name="start-the-check",
        document=policies.apply_scheduler_role_policy(
            region=region, account_id=account_id,
            check_state_machine=res.apply_check_state_machine,
        ),
    )

    api_role_arn = iam.create_role(
        iam_client,
        name=res.apply_api_role,
        trust=policies.service_trust("apigateway.amazonaws.com"),
        description="enclavize: the apply API invoking the state machine",
    )
    return {
        "boundary_arn": boundary_arn,
        "sfn_role_arn": sfn_role_arn,
        "scheduler_role_arn": scheduler_role_arn,
        "api_role_arn": api_role_arn,
    }


def launch_spec(ec2_client, ssm_client, *, res, ami_param: str, instance_type: str) -> dict:
    """What every instance the apply machinery launches is made of. Both
    machines launch, so both are built from this."""
    return {
        "image_id": ec2.resolve_ami(ssm_client, ami_param),
        "instance_type": instance_type,
        "subnet_id": ec2.default_subnet(ec2_client),
        "instance_profile": res.apply_role,
        "name_tag": res.apply_state_machine,
    }


def create_state_machine(sfn_client, ec2_client, ssm_client, *, res, app_repo: str, region: str,
                         account_id: str, domain: str, dashboard_bucket: str, role_arn: str,
                         scheduler_role_arn: str, ami_param: str, instance_type: str,
                         check_interval_minutes: int) -> str:
    """The receiving machine. Names the checking one by its derived ARN, so
    the two can be built in either order."""
    definition = statemachine.build_definition(
        app_repo=app_repo,
        domain=domain,
        **launch_spec(ec2_client, ssm_client, res=res, ami_param=ami_param,
                      instance_type=instance_type),
        dashboard_bucket=dashboard_bucket,
        check_state_machine_arn=check_state_machine_arn(res=res, region=region, account_id=account_id),
        schedule_name=res.apply_check_schedule,
        scheduler_role_arn=scheduler_role_arn,
        check_interval_minutes=check_interval_minutes,
        current_param=res.apply_current_param,
        pending_param=res.apply_pending_param,
        ready_param=res.apply_ready_param,
        in_flight_error=apigw.IN_FLIGHT_ERROR,
    )
    return sfn.create_state_machine(
        sfn_client, name=res.apply_state_machine, definition=definition, role_arn=role_arn,
    )


def create_check_machine(sfn_client, ec2_client, ssm_client, *, res, app_repo: str, domain: str,
                         dashboard_bucket: str, role_arn: str, ami_param: str, instance_type: str,
                         timeout_seconds: int) -> str:
    """The checking machine, Standard so its runs are kept: they are the only
    record of a switch having happened."""
    definition = checkmachine.build_definition(
        app_repo=app_repo,
        domain=domain,
        **launch_spec(ec2_client, ssm_client, res=res, ami_param=ami_param,
                      instance_type=instance_type),
        dashboard_bucket=dashboard_bucket,
        schedule_name=res.apply_check_schedule,
        current_param=res.apply_current_param,
        pending_param=res.apply_pending_param,
        ready_param=res.apply_ready_param,
        timeout_seconds=timeout_seconds,
    )
    return sfn.create_state_machine(
        sfn_client, name=res.apply_check_state_machine, definition=definition,
        role_arn=role_arn, kind=sfn.STANDARD,
    )


def create_api(apigw_client, iam_client, *, res, region: str, api_key: str, state_machine_arn: str,
               api_role_arn: str, account_id: str) -> str:
    """The REST API, its key, and the validator that guards the commit.

    A REST API rather than an HTTP one because only REST supports API keys.
    """
    iam.put_role_policy(
        iam_client, role=res.apply_api_role, name="start-the-apply",
        document={
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "states:StartSyncExecution", "Resource": state_machine_arn}
            ],
        },
    )

    api_id = apigw.create_api(apigw_client, name=res.apply_api_name, description="enclavize apply")
    root = apigw.root_resource_id(apigw_client, api_id)
    resource_id = apigw.create_resource(
        apigw_client, api_id=api_id, parent_id=root, path_part=config.APPLY_API_PATH
    )
    # The commit ends up in a shell command on the apply instance, so it is
    # rejected at the edge unless it is exactly a 40-hex sha.
    model = apigw.create_commit_model(
        apigw_client, api_id=api_id, name="ApplyRequest", pattern=config.COMMIT_PATTERN
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
    apigw.deploy(apigw_client, api_id=api_id, stage=config.APPLY_STAGE)

    key_id = apigw.create_api_key(apigw_client, name=res.apply_api_name, value=api_key)
    apigw.attach_key_to_plan(
        apigw_client, name=f"{res.apply_api_name}-plan", api_id=api_id,
        stage=config.APPLY_STAGE, key_id=key_id,
    )
    # The generated endpoint. Correct, but unreachable knowledge from outside:
    # nobody can look up the id in a sealed account. attach_custom_domain gives
    # it a name that can be worked out from the domain instead.
    url = apigw.invoke_url(
        api_id=api_id, region=region, stage=config.APPLY_STAGE, path=config.APPLY_API_PATH
    )
    # The id is needed to name this API in the boundary once it exists.
    return url, api_id


def attach_custom_domain(apigw_client, r53_client, *, api_id: str, domain: str,
                         certificate_arn: str, zone_id: str, region: str) -> str:
    """Put the API behind apply.{domain}. Returns the public endpoint.

    This is the only reason the endpoint is knowable at all. The setup program
    computes the generated execute-api URL and then throws it away — it runs on
    an instance that terminates itself, in an account with no console and no
    credentials, so a value only it ever saw is a value nobody has. Derived from
    the domain, the endpoint needs no channel to reach the operator.

    Must follow the certificate: a custom domain is rejected without one.
    """
    target = apigw.create_custom_domain(
        apigw_client, host=naming.apply_host(domain), certificate_arn=certificate_arn
    )
    apigw.map_base_path(
        apigw_client, host=naming.apply_host(domain), api_id=api_id,
        stage=config.APPLY_STAGE, base_path=config.APPLY_STAGE,
    )
    dns.change_records(
        r53_client,
        zone_id=zone_id,
        changes=[
            dns.upsert_alias(
                naming.apply_host(domain),
                target_dns=target["target_dns"],
                hosted_zone_id=target["target_zone"],
            )
        ],
        comment="enclavize apply endpoint",
    )
    return apigw.public_url(
        host=naming.apply_host(domain), stage=config.APPLY_STAGE, path=config.APPLY_API_PATH
    )
