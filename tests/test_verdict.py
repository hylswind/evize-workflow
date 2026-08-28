"""The judgement that decides whether a human touched the account.

The fixtures below are not invented: the sign-up sequence is what a real
account produced, dumped from CloudTrail before enclavize ran. An earlier
version of this check was written against guesses and would have failed that
account outright. The account id here is a placeholder; only the shape and
order of the events are real.
"""

from datetime import datetime, timedelta, timezone

from enclavize.logic import verdict

T0 = datetime(2026, 8, 25, 8, 48, 7, tzinfo=timezone.utc)
STARTED = T0 + timedelta(hours=1)  # when the workflow made its first call

# Every request id the run recorded. Anything during the run bearing another id
# was made by somebody else.
OWN = {"own-1", "own-2", "own-3"}


def event(name, source="iam.amazonaws.com", offset=0, region="us-east-1",
          is_root=True, request_id=None, invoked_by=None):
    return {
        "eventName": name,
        "eventSource": source,
        "eventTime": T0 + timedelta(seconds=offset),
        "region": region,
        "principal": "arn:aws:iam::123456789012:root" if is_root else "arn:aws:iam::1:user/enclavize",
        "isRoot": is_root,
        "requestID": request_id,
        # CloudTrail names the service here when one made the call for you.
        "invokedBy": invoked_by,
    }


def signup():
    """A real account's history, before enclavize ran."""
    return [
        event("SetAccountPlan", "signup.amazonaws.com", 0),
        event("CreateAccount", "signup.amazonaws.com", 127),
        event("CreatePaymentInstrument", "aws-payment-encryption.amazonaws.com", 203),
        event("Instruments_Create", "payments.amazonaws.com", 207),
        event("Preferences_CreatePaymentProfile", "payments.amazonaws.com", 208),
        event("EnableRegion", "signup.amazonaws.com", 254),
        event("SetIneligibleForFreeTierCredits", "signup.amazonaws.com", 282),
        event("SelectSupportPlan", "signup.amazonaws.com", 290),
        event("SubscribeToURP", "signup.amazonaws.com", 293),
        event("SetIAMAccessPreference", "billingconsole.amazonaws.com", 375),
        event("CreateAccessKey", "iam.amazonaws.com", 395),
    ]


ORGANIZATIONS = "organizations.amazonaws.com"


def the_organization_the_run_makes(at, created_by, deleted_by):
    """What creating and removing one really produced, taken from a real run.

    Two calls of enclavize's and four answers of AWS's. The list was wrong twice
    while this was written — `AccountJoinedOrganization` was missed first, then
    `AccountDepartedOrganization` — which is the argument for judging these on
    who made them rather than on a set of names somebody has to keep complete.
    """
    return [
        event("CreateOrganization", ORGANIZATIONS, at, request_id=created_by),
        event("AccountJoinedOrganization", ORGANIZATIONS, at, invoked_by=ORGANIZATIONS),
        event("CreateServiceLinkedRole", "iam.amazonaws.com", at, invoked_by=ORGANIZATIONS),
        event("CreateServiceLinkedRole", "iam.amazonaws.com", at, invoked_by=ORGANIZATIONS),
        event("DeleteOrganization", ORGANIZATIONS, at + 1, request_id=deleted_by),
        event("AccountDepartedOrganization", ORGANIZATIONS, at + 1, invoked_by=ORGANIZATIONS),
    ]


def sealed(*during):
    """A full clean history: sign-up, the run's own calls, then the seal."""
    return signup() + list(during) + [
        event("DeleteAccessKey", offset=7200, request_id="own-3"),
    ]


def judge(home, *, other=(), own=OWN, started=STARTED):
    return verdict.judge(
        home_events=home, other_region_events=list(other),
        own_request_ids=own, workflow_started_at=started,
    )


# --- the real account -----------------------------------------------------


def test_the_real_signup_sequence_passes():
    """A real account's actual history, plus a minimal run.

    The regression that matters: the previous version required CreateAccount to
    be the earliest event, and this account emits SetAccountPlan two minutes
    before it.
    """
    assert judge(sealed(event("CreateUser", offset=3700, request_id="own-1"))).ok


def test_the_workflows_own_calls_pass_by_request_id():
    history = sealed(
        event("CreateRole", offset=3700, request_id="own-1"),
        event("CreateUser", offset=3701, request_id="own-2"),
    )
    assert judge(history).ok


# --- the opening anchor ---------------------------------------------------


def test_a_window_that_opens_after_set_account_plan_is_caught():
    """The hole in "CreateAccount must merely be present": a window opening
    between SetAccountPlan and CreateAccount sees the creation, passes, and
    hides whatever came before."""
    truncated = signup()[1:]  # drops SetAccountPlan
    result = judge(truncated + [event("DeleteAccessKey", offset=7200, request_id="own-3")])
    assert not result.ok
    assert "hiding" in result.reason


def test_the_history_must_open_with_the_signup_pair():
    swapped = [signup()[1], signup()[0]] + signup()[2:]
    assert not judge(swapped).ok


def test_a_history_too_short_to_have_an_opening_is_caught():
    assert not judge([signup()[0]]).ok


# --- before the workflow --------------------------------------------------


def test_a_human_creating_a_user_before_the_workflow_is_caught():
    """iam:CreateUser is on no allow-list any more — the run's own calls are
    matched by request id instead, so a person's stand out."""
    history = signup() + [event("CreateUser", offset=400)] + [
        event("DeleteAccessKey", offset=7200, request_id="own-3")
    ]
    result = judge(history)
    assert not result.ok
    assert "by hand" in result.reason
    assert [e["eventName"] for e in result.unexpected] == ["CreateUser"]


def test_creating_the_organization_by_hand_is_caught():
    """It stopped being part of the procedure when the run started doing it, so
    a person doing it is an unexpected action like any other."""
    history = signup() + [
        event("CreateOrganization", ORGANIZATIONS, 500),
        event("DeleteAccessKey", offset=7200, request_id="own-3"),
    ]
    result = judge(history)
    assert not result.ok
    assert [e["eventName"] for e in result.unexpected] == ["CreateOrganization"]


def test_joining_somebody_elses_organization_is_still_caught():
    """The one Organizations call that would be a way back in: a member account
    carries a role its management account can assume. Allowing the creation of
    an organization must not allow accepting an invitation into one."""
    history = signup() + [
        event("AcceptHandshake", "organizations.amazonaws.com", 500),
        event("DeleteAccessKey", offset=7200, request_id="own-3"),
    ]
    result = judge(history)
    assert not result.ok
    assert [e["eventName"] for e in result.unexpected] == ["AcceptHandshake"]


def test_an_unseen_signup_event_passes():
    """Another account's sign-up may differ; the source is trusted whole."""
    history = signup() + [event("SomethingNew", "signup.amazonaws.com", 300)] + [
        event("DeleteAccessKey", offset=7200, request_id="own-3")
    ]
    assert judge(history).ok


def test_two_root_keys_are_caught():
    """The run deletes only the key it was given, so a second outlives the seal."""
    history = signup() + [event("CreateAccessKey", offset=400)] + [
        event("DeleteAccessKey", offset=7200, request_id="own-3")
    ]
    result = judge(history)
    assert not result.ok
    assert "outlive the seal" in result.reason


def test_minting_a_key_twice_fails_even_though_one_was_deleted():
    """Deliberate. The procedure mints one key; mint-delete-mint leaves one
    behind but is not a path anyone needs, and relaxing for it would only
    complicate the rule."""
    history = signup() + [
        event("DeleteAccessKey", offset=400),
        event("CreateAccessKey", offset=401),
        event("DeleteAccessKey", offset=7200, request_id="own-3"),
    ]
    assert not judge(history).ok


# --- during the workflow --------------------------------------------------


def test_an_extra_call_during_the_run_is_caught():
    """What a whitelist cannot see: the workflow creates users, so a person
    creating one more is indistinguishable by name. The request id is not."""
    history = sealed(
        event("CreateUser", offset=3700, request_id="own-1"),
        event("CreateUser", offset=3800, request_id="somebody-elses"),
    )
    result = judge(history)
    assert not result.ok
    assert "did not make" in result.reason
    assert [e["requestID"] for e in result.unexpected] == ["somebody-elses"]


def test_the_organization_the_run_makes_for_itself_passes():
    """Two calls of ours and four answers of AWS's. Only ours have ids we could
    ever have recorded; the rest say who made them instead."""
    assert judge(sealed(*the_organization_the_run_makes(3700, "own-1", "own-2"))).ok


def test_what_aws_did_is_named_rather_than_waved_through():
    """A run says what it allowed without an id, so it is on the record."""
    allowed = verdict.service_made(
        sealed(*the_organization_the_run_makes(3700, "own-1", "own-2")))
    assert [e["eventName"] for e in allowed] == [
        "AccountJoinedOrganization", "CreateServiceLinkedRole", "CreateServiceLinkedRole",
        "AccountDepartedOrganization",
    ]
    assert {e["invokedBy"] for e in allowed} == {ORGANIZATIONS}


def test_the_same_call_from_a_person_is_still_caught():
    """The name is not what lets it through — `invokedBy` is. Without it, an
    identical event fails, which is the whole difference."""
    history = sealed(
        event("CreateOrganization", ORGANIZATIONS, 3700, request_id="own-1"),
        event("CreateServiceLinkedRole", "iam.amazonaws.com", 3700),   # no invokedBy
    )
    result = judge(history)
    assert not result.ok
    assert [e["eventName"] for e in result.unexpected] == ["CreateServiceLinkedRole"]


def test_an_event_with_no_request_id_during_the_run_is_caught():
    history = sealed(event("CreateUser", offset=3700))
    assert not judge(history).ok


# --- identity and region --------------------------------------------------


def test_a_non_root_identity_is_ignored():
    """The instance's own calls, and the workflow's other identities, are not
    evidence: nobody was ever handed those credentials."""
    history = sealed(event("CreateUser", offset=3700, request_id="own-1"))
    history.append(event("RunInstances", "ec2.amazonaws.com", 9000, is_root=False))
    assert judge(history).ok


def test_a_root_write_in_another_region_fails():
    result = judge(
        sealed(event("CreateUser", offset=3700, request_id="own-1")),
        other=[event("RunInstances", "ec2.amazonaws.com", 3800, region="us-west-2")],
    )
    assert not result.ok
    assert "us-east-1" in result.reason


def test_a_non_root_write_in_another_region_is_ignored():
    assert judge(
        sealed(event("CreateUser", offset=3700, request_id="own-1")),
        other=[event("RunInstances", "ec2.amazonaws.com", 3800, region="us-west-2", is_root=False)],
    ).ok


# --- the seal -------------------------------------------------------------


def test_root_acting_after_the_seal_fails():
    history = sealed(event("CreateUser", offset=3700, request_id="own-1"))
    history.append(event("CreateUser", offset=8000, request_id="own-1"))
    result = judge(history)
    assert not result.ok
    assert "outlived the deletion" in result.reason


def test_a_history_with_no_seal_fails():
    result = judge(signup())
    assert not result.ok
    assert "not sealed" in result.reason


def test_someone_elses_early_key_deletion_cannot_truncate_the_audit():
    """Anchoring on the earliest DeleteAccessKey would let anyone end the window
    early and hide everything after it."""
    history = signup() + [
        event("DeleteAccessKey", offset=3700, request_id="own-1"),
        event("CreateUser", offset=3800, request_id="intruder"),
        event("DeleteAccessKey", offset=7200, request_id="own-3"),
    ]
    assert not judge(history).ok


# --- the report -----------------------------------------------------------


def test_the_report_never_prints_request_parameters():
    """Those fields can echo values that were passed in as secrets."""
    noisy = event("CreateUser", offset=400)
    noisy["requestParameters"] = {"password": "hunter2"}
    report = judge(signup() + [noisy]).report()
    assert "hunter2" not in report
    assert "requestParameters" not in report


def test_the_report_lists_pairs_ready_to_paste():
    report = judge(signup() + [event("Whatever", "acme.amazonaws.com", 400)]).report()
    assert '("acme.amazonaws.com", "Whatever"),' in report
