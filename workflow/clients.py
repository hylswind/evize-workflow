"""Sessions for the three identities a run acts as.

The run starts as root, hands off to the event reader to audit itself, then to
the starter to fire the go flag and publish proof. Each session is built from
explicit keys because the runner has no ambient credentials and must never pick
any up.

Every session can also record the request id of every call it makes. That is
what lets the audit distinguish enclavize's own calls from a person's: CloudTrail
reports the same id back as `requestID`, so the run can prove which events are
its own instead of inferring it from what the events look like.
"""

import boto3

from . import config


def _recorder(record):
    """Capture the request id of every call, whether or not it succeeded.

    A rejected API call still reaches AWS and is still logged by CloudTrail, and
    botocore raises it through `after-call` with a parsed error body that
    carries the id — so one hook covers both. `after-call-error` fires only when
    no request reached AWS at all, which leaves nothing in the history to
    reconcile against.
    """

    def capture(parsed, **_kwargs):
        request_id = (parsed or {}).get("ResponseMetadata", {}).get("RequestId")
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
        built.events.register("after-call.*.*", _recorder(record))
    return built
