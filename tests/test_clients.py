"""What the audit's attribution rests on: recording every request a run sends.

Offline. Building a session calls nothing, and emitting botocore's own events by
hand is exactly what botocore does around each HTTP attempt — so which hook is
registered can be pinned without reaching AWS.
"""

from workflow import clients


def responded(request_id):
    """What the hook is handed once an attempt gets a response."""
    return {"ResponseMetadata": {"RequestId": request_id, "HTTPStatusCode": 200}}


def rejected(request_id):
    """AWS refused it. The attempt still happened, and is still in the history."""
    return {
        "Error": {"Code": "InvalidParameterValue", "Message": "no"},
        "ResponseMetadata": {"RequestId": request_id, "HTTPStatusCode": 400},
    }


def recording():
    seen = set()
    return clients.session("AKIA", "secret", region="us-east-1", record=seen), seen


def attempt(session, parsed):
    session.events.emit(
        "response-received.ec2.RunInstances",
        parsed_response=parsed, response_dict=None, context={}, exception=None,
    )


def test_every_attempt_of_a_retried_call_is_recorded():
    """Why the hook is per-attempt. botocore retries throttling inside a single
    call; each attempt reaches AWS under its own id, and an id the run did not
    record reads as somebody else acting in the account."""
    session, seen = recording()
    attempt(session, rejected("throttled-1"))
    attempt(session, responded("succeeded-2"))
    assert seen == {"throttled-1", "succeeded-2"}


def test_the_per_call_hook_is_not_the_one_registered():
    """after-call fires once per call, after every retry has finished. Recording
    there would keep the last attempt's id and silently drop the rest."""
    session, seen = recording()
    session.events.emit("after-call.ec2.RunInstances", parsed=responded("req-1"), model=None)
    assert seen == set()


def test_a_rejected_attempt_is_recorded():
    session, seen = recording()
    attempt(session, rejected("refused-1"))
    assert seen == {"refused-1"}


def test_an_attempt_that_never_reached_aws_records_nothing():
    """No response, so no id — and nothing in the history to reconcile against."""
    session, seen = recording()
    attempt(session, None)
    assert seen == set()


def test_a_session_given_nothing_to_record_into_records_nothing():
    session = clients.session("AKIA", "secret", region="us-east-1")
    attempt(session, responded("req-1"))  # nothing registered, so nothing to raise
