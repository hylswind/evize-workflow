"""The state machine behind the deploy API.

It is Express and invoked synchronously, which is only viable because it does
one quick thing: launch an instance. It never waits for the deploy to finish —
that would blow through both the five-minute Express ceiling and API Gateway's
29-second integration timeout. Progress is watched on the dashboard instead.
"""

import json


def create_state_machine(sfn, *, name: str, definition: dict, role_arn: str) -> str:
    """Create an Express state machine. Returns its ARN."""
    return sfn.create_state_machine(
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
        type="EXPRESS",
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
