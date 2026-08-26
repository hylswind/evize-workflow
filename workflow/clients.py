"""Sessions for the three identities a run acts as.

The run starts as root, hands off to the event reader to audit itself, then to
the starter to fire the go flag and publish proof. Each session is built from
explicit keys because the runner has no ambient credentials and must never pick
any up.

Every session can also record the request id of every request it sends. That is
what lets the audit distinguish enclavize's own calls from a person's: CloudTrail
reports the same id back as `requestID`, so the run can prove which events are
its own instead of inferring it from what the events look like.
"""

import boto3

from . import config


RECORD_EVENT = "response-received.*.*"
"""Fired once per HTTP attempt, from inside botocore's retry loop.

Attempts are what CloudTrail records, so attempts are what has to be recorded.
botocore retries throttling and server errors within a single call, and each
attempt that reaches AWS is logged under its own request id; `after-call` fires
once per call and would capture only the last of them, leaving the earlier
attempts in the history looking like somebody else's work.
"""


def _recorder(record):
    """Capture the request id of every attempt, whether or not it succeeded.

    A rejected attempt still reached AWS and is still logged, and its error body
    carries the id the same way a successful one does. An attempt that never
    arrived has no response to read an id from, and leaves nothing in the
    history to reconcile against either.
    """

    def capture(parsed_response=None, **_kwargs):
        request_id = (parsed_response or {}).get("ResponseMetadata", {}).get("RequestId")
        if request_id:
            record.add(request_id)

    return capture


def session(access_key: str, secret_key: str, *, region: str = None, record=None) -> boto3.Session:
    built = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region or config.REGION,
    )
    if record is not None:
        built.events.register(RECORD_EVENT, _recorder(record))
    return built
