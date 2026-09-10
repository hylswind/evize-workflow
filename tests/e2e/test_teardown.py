"""The order a teardown removes things in, and what it looks for afterwards.

The steps live in scripts/dismantle.py; this is the only place their order is
pinned. Outside the ENCLAVIZE_E2E gate, like test_profile.py: no account, no
network.

Both tests here are regressions from one run. Deleting the usage plan before the
api it meters can only ever fail — AWS refuses a plan while an API stage is still
associated, and deleting the api is what clears that — so a plan was left behind.
The survey then reported the account clean, because it did not look at usage
plans, which is the failure that actually costs something: the next cycle would
have started against an account preflight had called ready.
"""

import dismantle
from harness import App, Profile, leftovers
from setup import config as setup_config

APIGW = "apigateway"
PROFILE = Profile(caller="acme/caller", domain="example.com", app=App(repo="acme/app"))


class FakeApiGateway:
    """Answers the surveys, and remembers the order it was asked to delete in."""

    ANSWERS = {
        "get_base_path_mappings": {"items": [{"basePath": "v1"}]},
        "get_rest_apis": {"items": [{"id": "a1", "name": "enclavize-apply-api"}]},
        "get_usage_plans": {"items": [{"id": "p1", "name": "enclavize-apply-api-plan"}]},
        "get_usage_plan_keys": {"items": [{"id": "k1"}]},
        "get_api_keys": {"items": [{"id": "ak1", "name": "enclavize-apply-api"}]},
        "get_domain_names": {"items": [{"domainName": "apply.example.com"}]},
    }

    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def call(**_kwargs):
            self.calls.append(name)
            return self.ANSWERS.get(name, {})
        return call


class Unreachable:
    """Every other service. leftovers() surveys inside a catch-all, so raising
    here is how a client says "nothing of mine is standing"."""

    def __getattr__(self, name):
        def call(*_args, **_kwargs):
            raise RuntimeError(f"{name} is not part of this test")
        return call


class Session:
    def __init__(self, apigw):
        self.apigw = apigw

    def client(self, name, **_kwargs):
        return self.apigw if name == APIGW else Unreachable()


def torn_down():
    apigw = FakeApiGateway()
    dismantle.delete_apply_api(Session(apigw), PROFILE.domain)
    return apigw.calls


def test_the_api_goes_before_the_plan_that_meters_it():
    """The plan is refused while an API stage is still associated with it, and
    deleting the api is what clears the association."""
    calls = torn_down()
    assert calls.index("delete_rest_api") < calls.index("delete_usage_plan")


def test_the_key_is_detached_before_the_plan_it_is_attached_to():
    calls = torn_down()
    assert calls.index("delete_usage_plan_key") < calls.index("delete_usage_plan")


def test_a_surviving_usage_plan_is_not_a_clean_account():
    """What made the survey agree with a teardown that had not finished."""
    apigw = FakeApiGateway()
    standing = leftovers(Session(apigw), "123456789012", PROFILE)
    assert "usage plan enclavize-apply-api-plan" in standing
    assert "api key enclavize-apply-api" in standing


def test_another_accounts_api_gateway_is_left_alone():
    """The survey is run against accounts that hold more than the enclave."""
    apigw = FakeApiGateway()
    apigw.ANSWERS = dict(FakeApiGateway.ANSWERS,
                         get_usage_plans={"items": [{"id": "p9", "name": "someone-elses"}]},
                         get_api_keys={"items": [{"id": "k9", "name": "someone-elses"}]})
    assert leftovers(Session(apigw), "123456789012", PROFILE) == [
        "rest api enclavize-apply-api", "custom domain apply.example.com"
    ]


# --- the whole order -------------------------------------------------------


class Nothing(dict):
    """An answer with nothing in it, whatever is asked of it."""

    def __getitem__(self, key):
        return []

    def get(self, key, default=None):
        return default


class Permissive:
    """A client that answers every call with nothing and notes what was asked."""

    def __init__(self, journal, service):
        self.journal, self.service = journal, service

    def get_paginator(self, name):
        self.journal.append((self.service, name))

        class Paginator:
            def paginate(_self, **_kwargs):
                return []

        return Paginator()

    def get_waiter(self, name):
        class Waiter:
            def wait(_self, **_kwargs):
                return None

        return Waiter()

    def __getattr__(self, name):
        def call(**kwargs):
            self.journal.append((self.service, name, kwargs.get("Name")))
            return Nothing()
        return call


class PermissiveSession:
    def __init__(self):
        self.journal = []

    def client(self, name, **_kwargs):
        return Permissive(self.journal, name)


def test_the_timer_goes_with_the_state_machines_and_every_parameter_goes_last():
    """The timer is the check machine's to delete in a live account; a
    teardown finds one only if an apply was accepted and never switched. The
    parameters go last of all, the ready flag among them — an application
    wrote it, but it is the enclave's to remove."""
    session = PermissiveSession()
    dismantle.everything(session, "123456789012", PROFILE.domain)
    first = {}
    for position, call in enumerate(session.journal):
        first.setdefault(call[:2], position)

    assert first[("stepfunctions", "list_state_machines")] < first[("scheduler", "list_schedules")]
    assert first[("scheduler", "list_schedules")] < first[("cloudfront", "list_distributions")]
    assert first[("acm", "list_certificates")] < first[("ssm", "delete_parameter")]

    deleted = [call[2] for call in session.journal if call[:2] == ("ssm", "delete_parameter")]
    assert deleted == [
        "/enclavize/go-flag",
        setup_config.RESOURCES.apply_current_param,
        setup_config.RESOURCES.apply_pending_param,
        setup_config.RESOURCES.apply_ready_param,
    ]


def test_a_timer_or_a_parameter_left_standing_is_not_a_clean_account():
    class Standing(Permissive):
        def get_paginator(self, name):
            class Paginator:
                def paginate(_self, **_kwargs):
                    return [{"Schedules": [{"Name": "enclavize-apply-check"}]}] \
                        if name == "list_schedules" else []

            return Paginator()

        def get_parameter(self, Name):
            return {"Parameter": {"Name": Name, "Value": "x"}}

    class StandingSession(PermissiveSession):
        def client(self, name, **_kwargs):
            return Standing(self.journal, name)

    standing = leftovers(StandingSession(), "123456789012", PROFILE)
    assert "schedule enclavize-apply-check" in standing
    assert f"parameter {setup_config.RESOURCES.apply_ready_param}" in standing
    assert "parameter /enclavize/go-flag" in standing
