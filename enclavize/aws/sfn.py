"""The two state machines behind the apply API.

The receiving one is Express and invoked synchronously, which is only viable
because it does one quick thing: decide, and launch. It never waits for
anything — that would blow through both the five-minute Express ceiling and
API Gateway's 29-second integration timeout.

The checking one is Standard, started by a timer rather than by anyone, and
does a few seconds' work each time: read the parameters, and either switch or
leave everything alone until the next look. Standard because its executions
are worth keeping — they are the only trace of a switch having happened.
"""

import json

EXPRESS = "EXPRESS"
STANDARD = "STANDARD"


def create_state_machine(sfn, *, name: str, definition: dict, role_arn: str,
                         kind: str = EXPRESS) -> str:
    """Create a state machine of the given kind. Returns its ARN."""
    return sfn.create_state_machine(
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
        type=kind,
    )["stateMachineArn"]


def start_sync(sfn, *, state_machine_arn: str, payload: dict) -> dict:
    """Run it and wait for the result.

    A 200 means the service accepted and ran the workflow, not that the workflow
    succeeded — status has to be read from the response body.
    """
    response = sfn.start_sync_execution(
        stateMachineArn=state_machine_arn, input=json.dumps(payload)
    )
    return {
        "status": response.get("status"),
        "output": json.loads(response["output"]) if response.get("output") else None,
        "error": response.get("error"),
        "cause": response.get("cause"),
    }


def delete_state_machine(sfn, state_machine_arn: str) -> None:
    sfn.delete_state_machine(stateMachineArn=state_machine_arn)
