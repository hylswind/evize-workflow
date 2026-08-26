"""The apply interface: state machine, REST API, certificate, distribution.

These pin request shapes. moto covers apigateway and stepfunctions well enough
to create real objects; ACM and CloudFront are driven through fakes where the
interesting behaviour is timing rather than storage.
"""

import json

import boto3
import pytest
from botocore.exceptions import ClientError
from constants import DOMAIN, REGION, clock, no_sleep
from moto import mock_aws

from enclavize.aws import acm as acmmod
from enclavize.aws import apigw, cdn, sfn

COMMIT_PATTERN = "^[0-9a-f]{40}$"


@pytest.fixture
def apigw_client():
    with mock_aws():
        yield boto3.client("apigateway", region_name=REGION)


@pytest.fixture
def sfn_client():
    with mock_aws():
        yield boto3.client("stepfunctions", region_name=REGION)


# --- Step Functions -------------------------------------------------------


def test_the_state_machine_is_express_so_it_can_answer_synchronously():
    """Only Express workflows support StartSyncExecution.

    Asserted on the request because moto stores every state machine as STANDARD
    regardless of what is sent; the real type is confirmed in tests/aws/.
    """
    recorded = {}

    class Recorder:
        def create_state_machine(self, **kwargs):
            recorded.update(kwargs)
            return {"stateMachineArn": "arn:sm"}

    sfn.create_state_machine(
        Recorder(), name="enclavize-apply",
        definition={"StartAt": "Done", "States": {"Done": {"Type": "Succeed"}}},
        role_arn="arn:aws:iam::123456789012:role/enclavize-apply-sfn",
    )
    assert recorded["type"] == "EXPRESS"


def test_the_definition_round_trips(sfn_client):
    role = "arn:aws:iam::123456789012:role/enclavize-apply-sfn"
    definition = {"StartAt": "Done", "States": {"Done": {"Type": "Succeed"}}}

    arn = sfn.create_state_machine(sfn_client, name="enclavize-apply", definition=definition, role_arn=role)

    described = sfn_client.describe_state_machine(stateMachineArn=arn)
    assert json.loads(described["definition"]) == definition


def test_a_sync_run_reports_status_separately_from_the_http_result():
    # A 200 only means the service ran the workflow; failure shows up in the body.
    class FakeSfn:
        def start_sync_execution(self, **kwargs):
            self.kwargs = kwargs
            return {"status": "FAILED", "error": "States.TaskFailed", "cause": "boom"}

    result = sfn.start_sync(FakeSfn(), state_machine_arn="arn:sm", payload={"commit": "a" * 40})
    assert result["status"] == "FAILED"
    assert result["error"] == "States.TaskFailed"


def test_the_payload_is_sent_as_json():
    class FakeSfn:
        def start_sync_execution(self, **kwargs):
            self.kwargs = kwargs
            return {"status": "SUCCEEDED", "output": json.dumps({"instanceId": "i-1"})}

    client = FakeSfn()
    result = sfn.start_sync(client, state_machine_arn="arn:sm", payload={"commit": "b" * 40})
    assert json.loads(client.kwargs["input"]) == {"commit": "b" * 40}
    assert result["output"] == {"instanceId": "i-1"}


# --- API Gateway ----------------------------------------------------------


def test_the_api_is_rest_because_http_apis_have_no_api_keys(apigw_client):
    api_id = apigw.create_api(apigw_client, name="enclavize-apply-api")
    described = apigw_client.get_rest_api(restApiId=api_id)
    assert described["apiKeySource"] == "HEADER"


def test_the_model_only_admits_a_well_formed_commit(apigw_client):
    api_id = apigw.create_api(apigw_client, name="enclavize-apply-api")
    apigw.create_commit_model(apigw_client, api_id=api_id, name="ApplyRequest", pattern=COMMIT_PATTERN)

    model = apigw_client.get_model(restApiId=api_id, modelName="ApplyRequest")
    schema = json.loads(model["schema"])
    assert schema["properties"]["commit"]["pattern"] == COMMIT_PATTERN
    assert schema["required"] == ["commit"]
    # Anything else in the body would otherwise ride along into the workflow.
    assert schema["additionalProperties"] is False


def test_the_method_demands_a_key_and_a_validated_body(apigw_client):
    api_id = apigw.create_api(apigw_client, name="enclavize-apply-api")
    root = apigw.root_resource_id(apigw_client, api_id)
    resource_id = apigw.create_resource(apigw_client, api_id=api_id, parent_id=root, path_part="commits")
    apigw.create_commit_model(apigw_client, api_id=api_id, name="ApplyRequest", pattern=COMMIT_PATTERN)
    validator_id = apigw.create_body_validator(apigw_client, api_id=api_id, name="body")

    apigw.put_key_protected_method(
        apigw_client, api_id=api_id, resource_id=resource_id, http_method="POST",
        model_name="ApplyRequest", validator_id=validator_id,
    )

    method = apigw_client.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="POST")
    assert method["apiKeyRequired"] is True
    assert method["requestModels"] == {"application/json": "ApplyRequest"}
    assert method["requestValidatorId"] == validator_id


def test_the_key_uses_the_value_the_operator_already_holds(apigw_client):
    # Generated server-side, the sealed account would have to hand it back out.
    key_id = apigw.create_api_key(apigw_client, name="enclavize-apply", value="k" * 32)
    stored = apigw_client.get_api_key(apiKey=key_id, includeValue=True)
    assert stored["value"] == "k" * 32
    assert stored["enabled"] is True


def test_the_key_is_bound_to_one_stage(apigw_client):
    api_id = apigw.create_api(apigw_client, name="enclavize-apply-api")
    key_id = apigw.create_api_key(apigw_client, name="enclavize-apply", value="k" * 32)

    plan_id = apigw.attach_key_to_plan(
        apigw_client, name="enclavize-apply-plan", api_id=api_id, stage="v1", key_id=key_id
    )

    plan = apigw_client.get_usage_plan(usagePlanId=plan_id)
    assert plan["apiStages"] == [{"apiId": api_id, "stage": "v1"}]


def test_the_integration_targets_start_sync_execution():
    recorded = {}

    class Recorder:
        def put_integration(self, **kwargs):
            recorded.update(kwargs)

        def put_method_response(self, **kwargs):
            pass

        def put_integration_response(self, **kwargs):
            pass

    apigw.put_state_machine_integration(
        Recorder(), api_id="api1", resource_id="res1", http_method="POST", region=REGION,
        credentials_arn="arn:aws:iam::1:role/api", state_machine_arn="arn:sm",
    )

    assert recorded["uri"] == f"arn:aws:apigateway:{REGION}:states:action/StartSyncExecution"
    assert recorded["type"] == "AWS"
    # NEVER: an unmatched content type must not slip through unmapped.
    assert recorded["passthroughBehavior"] == "NEVER"
    template = json.loads(recorded["requestTemplates"]["application/json"])
    assert template["stateMachineArn"] == "arn:sm"


def test_the_invoke_url_is_regional():
    url = apigw.invoke_url(api_id="abc123", region=REGION, stage="v1", path="commits")
    assert url == f"https://abc123.execute-api.{REGION}.amazonaws.com/v1/commits"


# --- the custom domain ----------------------------------------------------
#
# The generated endpoint above is unusable knowledge: the account is sealed, so
# nobody can look up the id. These pin the name that can be derived instead.


def test_the_public_url_needs_only_the_domain():
    assert apigw.public_url(host=f"apply.{DOMAIN}", stage="v1", path="commits") == (
        f"https://apply.{DOMAIN}/v1/commits"
    )


def test_the_custom_domain_is_regional_like_the_api(apigw_client):
    """The endpoint types have to match, and regional avoids building a
    CloudFront distribution that would spend half an hour propagating."""
    recorded = {}

    class Recorder:
        def create_domain_name(self, **kwargs):
            recorded.update(kwargs)
            return {"regionalDomainName": "d-x.execute-api.us-east-1.amazonaws.com",
                    "regionalHostedZoneId": "ZONE"}

    target = apigw.create_custom_domain(
        Recorder(), host=f"apply.{DOMAIN}", certificate_arn="arn:cert"
    )
    assert recorded["endpointConfiguration"] == {"types": ["REGIONAL"]}
    # A regional domain reads its certificate from the regional field; passing
    # certificateArn instead is silently ignored and the domain serves nothing.
    assert recorded["regionalCertificateArn"] == "arn:cert"
    assert "certificateArn" not in recorded
    assert target == {"target_dns": "d-x.execute-api.us-east-1.amazonaws.com",
                      "target_zone": "ZONE"}


def test_the_alias_target_comes_from_the_response(apigw_client):
    """Not constructed: the regional endpoint's hosted zone id is AWS's to
    choose, and hardcoding one would point the alias at the wrong region."""
    apigw_client.create_domain_name(
        domainName=f"apply.{DOMAIN}", regionalCertificateArn="arn:cert",
        endpointConfiguration={"types": ["REGIONAL"]},
    )
    described = apigw_client.get_domain_name(domainName=f"apply.{DOMAIN}")
    assert described["regionalDomainName"]
    assert described["regionalHostedZoneId"]


def test_the_stage_stays_in_the_path(apigw_client):
    """Omitting basePath maps the stage at the root and the stage name vanishes
    from the URL, leaving nowhere to put a second one later."""
    api_id = apigw.create_api(apigw_client, name="enclavize-apply")
    root = apigw.root_resource_id(apigw_client, api_id)
    resource_id = apigw.create_resource(
        apigw_client, api_id=api_id, parent_id=root, path_part="commits"
    )
    apigw_client.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="POST",
                            authorizationType="NONE", apiKeyRequired=True)
    apigw_client.put_integration(restApiId=api_id, resourceId=resource_id, httpMethod="POST",
                                 type="MOCK", integrationHttpMethod="POST")
    apigw.deploy(apigw_client, api_id=api_id, stage="v1")
    apigw_client.create_domain_name(
        domainName=f"apply.{DOMAIN}", regionalCertificateArn="arn:cert",
        endpointConfiguration={"types": ["REGIONAL"]},
    )
    apigw.map_base_path(
        apigw_client, host=f"apply.{DOMAIN}", api_id=api_id, stage="v1", base_path="v1"
    )
    mapping = apigw_client.get_base_path_mappings(domainName=f"apply.{DOMAIN}")["items"][0]
    assert mapping["basePath"] == "v1"
    assert mapping["stage"] == "v1"


# --- ACM ------------------------------------------------------------------


class FakeAcm:
    def __init__(self, states):
        self.states = list(states)
        self.requests = []

    def request_certificate(self, **kwargs):
        self.requests.append(kwargs)
        return {"CertificateArn": "arn:cert"}

    def describe_certificate(self, **kwargs):
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return {"Certificate": state}


def test_the_certificate_covers_every_public_host():
    """All three names ride on one certificate — apply. included, since a custom
    domain is rejected without one."""
    client = FakeAcm([{"Status": "ISSUED"}])
    names = [f"dashboard.{DOMAIN}", f"proof.{DOMAIN}", f"apply.{DOMAIN}"]
    acmmod.request_certificate(
        client, domain=DOMAIN, alternative_names=names, idempotency_token="tok",
    )
    assert client.requests[0]["ValidationMethod"] == "DNS"
    assert client.requests[0]["SubjectAlternativeNames"] == names


def test_validation_records_are_waited_for_rather_than_read_once():
    # They are not present the instant the certificate is requested.
    record = {"Name": "_x.example.com", "Value": "_y.acm.aws", "Type": "CNAME"}
    client = FakeAcm(
        [
            {"DomainValidationOptions": [{"DomainName": DOMAIN}]},
            {"DomainValidationOptions": [{"DomainName": DOMAIN, "ResourceRecord": record}]},
        ]
    )
    records = acmmod.validation_records(client, "arn:cert", poll_max=120, interval=5,
                                        sleep=no_sleep, now=clock([0, 1, 2]))
    assert records == [record]


def test_duplicate_validation_records_collapse():
    record = {"Name": "_x.example.com", "Value": "_y.acm.aws", "Type": "CNAME"}
    client = FakeAcm(
        [{"DomainValidationOptions": [
            {"DomainName": DOMAIN, "ResourceRecord": record},
            {"DomainName": f"dashboard.{DOMAIN}", "ResourceRecord": record},
        ]}]
    )
    records = acmmod.validation_records(client, "arn:cert", poll_max=120, interval=5,
                                        sleep=no_sleep, now=clock([0, 1]))
    assert len(records) == 1


def test_waiting_for_issue_succeeds():
    client = FakeAcm([{"Status": "PENDING_VALIDATION"}, {"Status": "ISSUED"}])
    acmmod.await_issued(client, "arn:cert", poll_max=2700, interval=30,
                        sleep=no_sleep, now=clock([0, 1, 2]))


def test_a_validation_timeout_blames_delegation_because_that_is_the_usual_cause():
    client = FakeAcm([{"Status": "PENDING_VALIDATION"}])
    with pytest.raises(TimeoutError, match="nameserver delegation"):
        acmmod.await_issued(client, "arn:cert", poll_max=2700, interval=30,
                            sleep=no_sleep, now=clock([0, 99999]))


def test_a_failed_certificate_raises_with_its_reason():
    client = FakeAcm([{"Status": "FAILED", "FailureReason": "DOMAIN_NOT_ALLOWED"}])
    with pytest.raises(RuntimeError, match="DOMAIN_NOT_ALLOWED"):
        acmmod.await_issued(client, "arn:cert", poll_max=60, interval=5,
                            sleep=no_sleep, now=clock([0, 1]))


# --- CloudFront -----------------------------------------------------------


def test_the_distribution_serves_a_private_bucket_over_https():
    recorded = {}

    class Recorder:
        def create_distribution(self, **kwargs):
            recorded.update(kwargs)
            return {"Distribution": {"Id": "E1", "ARN": "arn:cf", "DomainName": "d1.cloudfront.net"}}

    result = cdn.create_distribution(
        Recorder(), caller_reference="ref", bucket="enclavize-proof-1", region=REGION,
        aliases=[f"proof.{DOMAIN}"], certificate_arn="arn:cert", oac_id="oac1",
    )

    config = recorded["DistributionConfig"]
    origin = config["Origins"]["Items"][0]
    assert origin["DomainName"] == f"enclavize-proof-1.s3.{REGION}.amazonaws.com"
    assert origin["OriginAccessControlId"] == "oac1"
    assert config["DefaultCacheBehavior"]["ViewerProtocolPolicy"] == "redirect-to-https"
    assert config["ViewerCertificate"]["ACMCertificateArn"] == "arn:cert"
    assert config["Aliases"]["Items"] == [f"proof.{DOMAIN}"]
    # The ARN is needed before the bucket policy can name this distribution.
    assert result["arn"] == "arn:cf"


def test_an_origin_access_control_that_already_exists_is_reused():
    """Names are unique per account and outlive the distributions that used
    them, so a bring-up reaching this point a second time would otherwise fail
    with everything before it already built."""

    class Taken:
        def create_origin_access_control(self, **_kwargs):
            raise ClientError(
                {"Error": {"Code": "OriginAccessControlAlreadyExists", "Message": "exists"}},
                "CreateOriginAccessControl",
            )

        def get_paginator(self, _name):
            class Pages:
                def paginate(self):
                    return [{"OriginAccessControlList": {"Items": [
                        {"Id": "OTHER", "Name": "someone-elses-oac"},
                        {"Id": "E123", "Name": "enclavize-proof-1-oac"},
                    ]}}]

            return Pages()

    assert cdn.create_origin_access_control(Taken(), name="enclavize-proof-1-oac") == "E123"


def test_an_unfindable_origin_access_control_is_an_error_not_a_guess():
    class Taken:
        def create_origin_access_control(self, **_kwargs):
            raise ClientError(
                {"Error": {"Code": "OriginAccessControlAlreadyExists", "Message": "exists"}},
                "CreateOriginAccessControl",
            )

        def get_paginator(self, _name):
            class Pages:
                def paginate(self):
                    return [{"OriginAccessControlList": {"Items": []}}]

            return Pages()

    with pytest.raises(RuntimeError, match="cannot be found"):
        cdn.create_origin_access_control(Taken(), name="enclavize-proof-1-oac")


def test_any_other_creation_failure_still_propagates():
    class Denied:
        def create_origin_access_control(self, **_kwargs):
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "no"}},
                "CreateOriginAccessControl",
            )

    with pytest.raises(ClientError):
        cdn.create_origin_access_control(Denied(), name="x")


def test_deleting_an_origin_access_control_passes_the_current_etag():
    """CloudFront rejects the delete without IfMatch, and only a read has it."""
    calls = {}

    class Fake:
        def get_origin_access_control(self, **kwargs):
            calls["get"] = kwargs
            return {"ETag": "E-TAG"}

        def delete_origin_access_control(self, **kwargs):
            calls["delete"] = kwargs

    cdn.delete_origin_access_control(Fake(), "E123")
    assert calls["delete"] == {"Id": "E123", "IfMatch": "E-TAG"}


def test_origin_access_control_signs_every_request():
    recorded = {}

    class Recorder:
        def create_origin_access_control(self, **kwargs):
            recorded.update(kwargs)
            return {"OriginAccessControl": {"Id": "oac1"}}

    cdn.create_origin_access_control(Recorder(), name="enclavize-proof")
    config = recorded["OriginAccessControlConfig"]
    assert config["SigningBehavior"] == "always"
    assert config["OriginAccessControlOriginType"] == "s3"


def test_await_deployed_reports_when_the_alias_becomes_usable():
    class Deploying:
        def __init__(self):
            self.n = 0

        def get_distribution(self, Id):
            self.n += 1
            status = "InProgress" if self.n < 2 else "Deployed"
            return {"Distribution": {"Status": status}}

    assert cdn.await_deployed(Deploying(), "E1", poll_max=1800, interval=30,
                              sleep=no_sleep, now=clock([0, 1, 2]))


def test_await_deployed_gives_up_without_raising():
    class Stuck:
        def get_distribution(self, Id):
            return {"Distribution": {"Status": "InProgress"}}

    assert cdn.await_deployed(Stuck(), "E1", poll_max=1800, interval=30,
                              sleep=no_sleep, now=clock([0, 99999])) is False


def test_disabling_is_a_no_op_when_already_disabled():
    # Teardown may run twice; the second pass must not fail.
    class AlreadyOff:
        def get_distribution(self, Id):
            return {"ETag": "e1", "Distribution": {"DistributionConfig": {"Enabled": False}}}

        def update_distribution(self, **kwargs):
            raise AssertionError("should not update an already-disabled distribution")

    cdn.disable(AlreadyOff(), "E1")


