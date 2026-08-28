"""Judge a window of CloudTrail events: did anyone else act in this account?

This module does the deciding; enclavize.aws.events does the fetching. Keeping
them apart means the judgement is offline-testable against canned event lists,
which matters because it had to be corrected against a real account's history.

**Only root is examined.** Root is the one credential a person was ever handed;
the admin role, the event reader and the starter are minted by the workflow
inside the runner and never leave it. What the instance does, and what the
workflow's own identities do, is not evidence of anything.

Watching root alone is sufficient rather than merely convenient: root is the
only way in, so an operator who minted themselves another identity to work
through would have to call CreateUser as root to do it. Every escalation leaves
a root-produced trace at its root.

The history is judged in two halves, split at the moment the workflow made its
first call:

- Before that, a small allow-list covers what the operator's manual pre-steps
  produce — signing up, and minting the root key.
- After it, every root event must carry a request id the workflow itself
  recorded. That is attribution rather than pattern-matching: it catches an
  extra call even when the call looks exactly like one enclavize makes.

Two ordering rules bracket the whole thing, for different reasons. The tail is
the security property itself — root's key deletion must be the last thing root
ever does. The head proves the window was not truncated: requiring only that
CreateAccount be present would let a window that opened *after* the account's
first event pass while hiding everything before it.
"""

from dataclasses import dataclass, field

# Services reachable only through the sign-up portal and the billing console.
# Whitelisted whole rather than event by event, because the damage available
# through them is bounded: support plan, payment method, free-tier eligibility,
# region opt-in, the IAM billing preference. None of it changes which account
# holds which domain, which is what the statement claims. The cost is being
# blind to operations AWS adds under these sources later; the benefit is that
# accounts whose sign-up differs are not failed for it.
TRUSTED_SOURCES = frozenset(
    {
        "signup.amazonaws.com",
        "payments.amazonaws.com",
        "aws-payment-encryption.amazonaws.com",
        "billingconsole.amazonaws.com",
    }
)

# What the operator does by hand before the workflow runs, and nothing else.
# Everything enclavize itself does is matched by request id, so it deliberately
# does not appear here — which is what makes a person creating a user or a role
# before the run detectable.
#
# Minting the root key is the whole of it. Creating an organization was once
# here too, when it was a manual step; the run makes its own now, so a person
# doing it by hand is an unexpected action and belongs on no list.
PREFLIGHT_WHITELIST = frozenset({("iam.amazonaws.com", "CreateAccessKey")})

# The account's history opens with these two, in this order, on every account
# observed so far.
OPENING_SEQUENCE = (
    ("signup.amazonaws.com", "SetAccountPlan"),
    ("signup.amazonaws.com", "CreateAccount"),
)

ROOT_KEY_EVENT = "CreateAccessKey"
SEAL_EVENT = "DeleteAccessKey"


@dataclass(frozen=True)
class Verdict:
    ok: bool
    unexpected: list = field(default_factory=list)
    reason: str = ""

    def report(self) -> str:
        """A failure report safe to print in a public CI log.

        Only identifying fields are included. requestParameters and
        responseElements are deliberately never printed: they can carry values
        that were passed in as secrets.
        """
        if self.ok:
            return "event check passed"
        lines = [self.reason or "unexpected activity in this account:"]
        for event in self.unexpected:
            lines.append(
                "  {region} {time} {source} {name} by {who}".format(
                    region=event.get("region", "?"),
                    time=event.get("eventTime", "?"),
                    source=event.get("eventSource", "?"),
                    name=event.get("eventName", "?"),
                    who=event.get("principal", "?"),
                )
            )
        pairs = sorted({(e.get("eventSource", "?"), e.get("eventName", "?")) for e in self.unexpected})
        if pairs:
            lines.append("")
            lines.append("pairs seen but not accounted for:")
            for source, name in pairs:
                lines.append(f'        ("{source}", "{name}"),')
        return "\n".join(lines)


def _at(event):
    return event.get("eventTime")


def _pair(event):
    return (event.get("eventSource"), event.get("eventName"))


def root_events(events):
    """Only what root did, oldest first. Everything else is not evidence."""
    return sorted((e for e in events if e.get("isRoot")), key=lambda e: _at(e) or "")


def find_root_seal(events):
    """Root deleting its own access key, or None.

    Deliberately not "the earliest DeleteAccessKey": anyone deleting any key
    would then close the window early and hide everything after it. If there
    were several, the last one is the one that ends root.
    """
    matches = [e for e in events if e.get("eventName") == SEAL_EVENT]
    return max(matches, key=_at) if matches else None


def _check_opening(ordered):
    """The window must reach back to the account's first moments."""
    expected = " then ".join(f"{s}/{n}" for s, n in OPENING_SEQUENCE)
    if len(ordered) < len(OPENING_SEQUENCE):
        return Verdict(
            ok=False,
            unexpected=list(ordered),
            reason=(
                f"the history holds only {len(ordered)} root event(s); an account opens "
                f"with {expected}, so this window does not reach back to its creation:"
            ),
        )
    if tuple(_pair(e) for e in ordered[: len(OPENING_SEQUENCE)]) != OPENING_SEQUENCE:
        return Verdict(
            ok=False,
            unexpected=list(ordered[: len(OPENING_SEQUENCE)]),
            reason=(
                f"the history should open with {expected}. It does not, so either the "
                "audited window began after the account's first events and is hiding "
                "them, or sign-up did not proceed normally:"
            ),
        )
    return None


def _check_preflight(before):
    """What the operator did by hand, before the workflow existed."""
    unexpected = [
        e for e in before
        if e.get("eventSource") not in TRUSTED_SOURCES and _pair(e) not in PREFLIGHT_WHITELIST
    ]
    if unexpected:
        return Verdict(
            ok=False,
            unexpected=unexpected,
            reason=(
                f"{len(unexpected)} root event(s) before the workflow started that are not "
                "part of signing up or minting the root key — someone did more by hand "
                "than the procedure calls for:"
            ),
        )

    # The workflow deletes the key it was handed and no other, so a second key
    # would outlive the seal. The documented procedure mints one; anything else
    # is worth stopping for, including a mint-delete-mint that happens to leave
    # one behind. Relaxing for a path nobody needs only complicates the rule.
    minted = [e for e in before if e.get("eventName") == ROOT_KEY_EVENT]
    if len(minted) != 1:
        return Verdict(
            ok=False,
            unexpected=minted,
            reason=(
                f"root created {len(minted)} access key(s) before the workflow ran, and "
                "the procedure mints exactly one. The workflow deletes only the key it "
                "was given, so any other would outlive the seal:"
            ),
        )
    return None


def made_by_aws(event) -> bool:
    """Whether an AWS service made this call on the account's behalf.

    CloudTrail names the service in userIdentity.invokedBy when one did, and
    leaves it out when a person did. It is built from the authenticated
    principal rather than from anything the caller sends, so it is not a header
    somebody can type — which is why this leans on it and not on userAgent,
    which says the same thing and can be set to anything.
    """
    return bool(event.get("invokedBy"))


def service_made(events) -> list:
    """The root events an AWS service made, so a run can say what it allowed.

    Passing silently would hide the one thing this rule lets through; a run that
    names them puts them on the record instead.
    """
    return [e for e in root_events(events) if made_by_aws(e)]


def _check_attribution(during, own_request_ids):
    """Every root call during the run is one the workflow made, or one AWS made
    for it.

    The second half is not a relaxation into pattern-matching: it asks the same
    question the first does — who made this call — for the case enclavize cannot
    answer with a request id. Creating an organization is one boto3 call that
    AWS answers with three of its own, and their ids never reach the caller.
    """
    unexpected = [
        e for e in during
        if e.get("requestID") not in own_request_ids and not made_by_aws(e)
    ]
    if unexpected:
        return Verdict(
            ok=False,
            unexpected=unexpected,
            reason=(
                f"{len(unexpected)} root event(s) during the run that enclavize did not "
                "make — their request ids are not among the calls it issued, and no AWS "
                "service claims them:"
            ),
        )
    return None


def judge(
    *,
    home_events,
    other_region_events,
    own_request_ids,
    workflow_started_at,
    home_region="us-east-1",
):
    """Decide whether only the sealing flow acted in this account.

    `home_events` and `other_region_events` arrive from aws.events already
    filtered to non-read-only. `own_request_ids` is every request id the run's
    own sessions recorded; `workflow_started_at` is when it made its first call.
    """
    ordered = root_events(home_events)
    if not ordered:
        return Verdict(ok=False, reason="no root activity at all: this is not the account's own history")

    opening = _check_opening(ordered)
    if opening:
        return opening

    before = [e for e in ordered if _at(e) and _at(e) < workflow_started_at]
    during = [e for e in ordered if _at(e) and _at(e) >= workflow_started_at]

    for check in (_check_preflight(before), _check_attribution(during, own_request_ids)):
        if check:
            return check

    seal = find_root_seal(ordered)
    if seal is None:
        return Verdict(
            ok=False,
            reason=(
                f"root never deleted its own access key (no {SEAL_EVENT} by root): "
                "the account is not sealed"
            ),
        )
    after_seal = [e for e in ordered if _at(e) and _at(e) > _at(seal)]
    if after_seal:
        return Verdict(
            ok=False,
            unexpected=after_seal,
            reason=(
                f"root acted {len(after_seal)} time(s) after deleting its own key: the "
                "credential outlived the deletion that was meant to end it:"
            ),
        )

    # enclavize only ever works in one region, so root anywhere else is a person.
    elsewhere = [e for e in other_region_events if e.get("isRoot")]
    if elsewhere:
        return Verdict(
            ok=False,
            unexpected=elsewhere,
            reason=(
                f"{len(elsewhere)} root event(s) outside {home_region}, where enclavize "
                "never operates:"
            ),
        )

    return Verdict(ok=True)
