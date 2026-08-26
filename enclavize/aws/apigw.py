"""The apply API.

A REST API rather than an HTTP API, because only REST supports API keys and the
key is the whole access control story here.

The request validator matters as much as the key: the commit reaches a shell
command inside an instance's user-data, so a malformed one is rejected at the
edge rather than deeper in.
"""


def create_api(apigw, *, name: str, description: str = "") -> str:
    return apigw.create_rest_api(
        name=name,
        description=description,
        apiKeySource="HEADER",
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]


def root_resource_id(apigw, api_id: str) -> str:
    resources = apigw.get_resources(restApiId=api_id)["items"]
    return next(item["id"] for item in resources if item["path"] == "/")


def create_resource(apigw, *, api_id: str, parent_id: str, path_part: str) -> str:
    return apigw.create_resource(restApiId=api_id, parentId=parent_id, pathPart=path_part)["id"]


def create_commit_model(apigw, *, api_id: str, name: str, pattern: str) -> str:
    """A body schema that only admits a well-formed commit sha."""
    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "title": name,
        "type": "object",
        "properties": {"commit": {"type": "string", "pattern": pattern}},
        "required": ["commit"],
        "additionalProperties": False,
    }
    import json

    apigw.create_model(
        restApiId=api_id,
        name=name,
        contentType="application/json",
        schema=json.dumps(schema),
    )
    return name


def create_body_validator(apigw, *, api_id: str, name: str) -> str:
    return apigw.create_request_validator(
        restApiId=api_id,
        name=name,
        validateRequestBody=True,
        validateRequestParameters=False,
    )["id"]


def put_key_protected_method(apigw, *, api_id: str, resource_id: str, http_method: str,
                             model_name: str, validator_id: str) -> None:
    """A method that requires an API key and a body matching the model."""
    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        authorizationType="NONE",
        apiKeyRequired=True,
        requestModels={"application/json": model_name},
        requestValidatorId=validator_id,
    )


def put_state_machine_integration(apigw, *, api_id: str, resource_id: str, http_method: str,
                                  region: str, credentials_arn: str, state_machine_arn: str) -> None:
    """Wire the method straight to StartSyncExecution — no Lambda in between.

    The mapping template hands the state machine only the validated commit, so
    nothing else from the request body can reach it.
    """
    import json

    template = json.dumps(
        {
            "input": "$util.escapeJavaScript($input.json('$'))",
            "stateMachineArn": state_machine_arn,
        }
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type="AWS",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{region}:states:action/StartSyncExecution",
        credentials=credentials_arn,
        requestTemplates={"application/json": template},
        passthroughBehavior="NEVER",
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200",
        responseModels={"application/json": "Empty"},
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200",
        responseTemplates={"application/json": STATE_MACHINE_RESPONSE},
    )


STATE_MACHINE_RESPONSE = (
    "#if($input.path('$.status') == 'SUCCEEDED')"
    "$input.path('$.output')"
    "#else"
    '{"status":"$input.path(\'$.status\')",'
    '"error":"$input.path(\'$.error\')",'
    '"cause":"$input.path(\'$.cause\')"}'
    "#end"
)
"""What the caller gets back.

The state machine's own answer, not the envelope StartSyncExecution wraps it
in — which carries billing figures, an execution ARN and internal type names,
and buries the useful part in a JSON string that has to be parsed twice.

A failure still has to say so: an HTTP 200 here means only that the service ran
the workflow, so anything other than SUCCEEDED returns the reason instead.
"""


def deploy(apigw, *, api_id: str, stage: str) -> None:
    apigw.create_deployment(restApiId=api_id, stageName=stage)


def create_api_key(apigw, *, name: str, value: str) -> str:
    """Create a key with a caller-supplied value.

    The value comes from a repository secret so the operator already holds it
    and the sealed account never has to hand it back out.
    """
    return apigw.create_api_key(name=name, value=value, enabled=True)["id"]


def attach_key_to_plan(apigw, *, name: str, api_id: str, stage: str, key_id: str) -> str:
    """A usage plan binding the key to one stage. Returns the plan id."""
    plan_id = apigw.create_usage_plan(
        name=name,
        apiStages=[{"apiId": api_id, "stage": stage}],
    )["id"]
    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    return plan_id


def create_custom_domain(apigw, *, host: str, certificate_arn: str) -> dict:
    """A name of our own in front of the API. Returns the Route 53 alias target.

    Regional rather than edge-optimized, which the API itself already is: the
    endpoint types have to match, and an edge domain would build a CloudFront
    distribution of its own and spend half an hour propagating. Regional is
    immediate and its certificate is the same us-east-1 one everything else
    uses.
    """
    created = apigw.create_domain_name(
        domainName=host,
        regionalCertificateArn=certificate_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        securityPolicy="TLS_1_2",
    )
    return {
        "target_dns": created["regionalDomainName"],
        "target_zone": created["regionalHostedZoneId"],
    }


def map_base_path(apigw, *, host: str, api_id: str, stage: str, base_path: str) -> None:
    """Put the stage under a path on the custom domain.

    base_path is passed explicitly rather than left out: omitting it maps the
    stage at the root and the stage name vanishes from the URL, which would
    leave no room for a second one later.
    """
    apigw.create_base_path_mapping(
        domainName=host, restApiId=api_id, stage=stage, basePath=base_path
    )


def invoke_url(*, api_id: str, region: str, stage: str, path: str) -> str:
    """The generated endpoint. Still the truth, but nobody outside can read it:
    the account is sealed, so the custom domain is how anyone reaches this."""
    return f"https://{api_id}.execute-api.{region}.amazonaws.com/{stage}/{path}"


def public_url(*, host: str, stage: str, path: str) -> str:
    """The endpoint an operator can work out from the domain alone."""
    return f"https://{host}/{stage}/{path}"


def delete_api(apigw, api_id: str) -> None:
    apigw.delete_rest_api(restApiId=api_id)


def delete_custom_domain(apigw, host: str) -> None:
    apigw.delete_domain_name(domainName=host)


def delete_usage_plan(apigw, *, plan_id: str, key_id: str = None) -> None:
    if key_id:
        apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    apigw.delete_usage_plan(usagePlanId=plan_id)


def delete_api_key(apigw, key_id: str) -> None:
    apigw.delete_api_key(apiKey=key_id)
