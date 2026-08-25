"""Audit the sealing: did anyone else act in this account?

Reads with the event reader's credentials — root's are gone by now. Fetching is
enclavize.aws.events, judging is enclavize.logic.verdict; this step only sweeps
the regions and hands the two together.
"""

from enclavize.aws import ec2, events
from enclavize.logic import verdict as verdict_logic


def verify(ct_client, ec2_client, client_for_region, *, start, end, home_region: str,
           poll_max: int, interval: int, own_request_ids, workflow_started_at):
    """Return a Verdict over [start, end].

    The home region is polled until the account's creation has been delivered —
    history lags by roughly fifteen minutes — while `end` stays fixed so the
    window cannot widen underneath the check.
    """
    home_events = events.await_event(
        ct_client,
        region=home_region,
        start=start,
        end=end,
        event_name=verdict_logic.OPENING_SEQUENCE[-1][1],
        poll_max=poll_max,
        interval=interval,
    )
    # Every other region must be silent: enclavize never touches them, so a
    # write there is somebody else by construction.
    other = events.sweep_other_regions(
        client_for_region,
        regions=ec2.enabled_regions(ec2_client),
        home_region=home_region,
        start=start,
        end=end,
    )
    return verdict_logic.judge(
        home_events=home_events,
        other_region_events=other,
        own_request_ids=own_request_ids,
        workflow_started_at=workflow_started_at,
        home_region=home_region,
    )
