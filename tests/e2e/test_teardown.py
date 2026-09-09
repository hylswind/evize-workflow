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
from botocore.exceptions import ClientError
from harness import App, Profile, leftovers

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


# --- the front door --------------------------------------------------------


class FakeElbv2:
    """One balancer with two listeners, and two target groups a switch left."""

    def __init__(self):
        self.calls = []

    def get_paginator(self, name):
        answers = {
            "describe_load_balancers": [{"LoadBalancers": [
                {"LoadBalancerArn": "arn:lb", "LoadBalancerName": "enclavize-app"},
                {"LoadBalancerArn": "arn:theirs", "LoadBalancerName": "theirs"},
            ]}],
            "describe_target_groups": [{"TargetGroups": [
                {"TargetGroupArn": "arn:tg1", "TargetGroupName": "enclavize-app-0123abcd"},
                {"TargetGroupArn": "arn:tg2", "TargetGroupName": "enclavize-app-4567efgh"},
                {"TargetGroupArn": "arn:tg9", "TargetGroupName": "theirs"},
            ]}],
            "describe_listeners": [{"Listeners": [
                {"ListenerArn": "arn:lb/l80"}, {"ListenerArn": "arn:lb/l443"},
            ]}],
        }

        class Paginator:
            def paginate(_self, **kwargs):
                return answers[name]

        return Paginator()

    def describe_load_balancers(self, **kwargs):
        # Asked only by the wait, after the delete: it has gone.
        self.calls.append("describe_load_balancers")
        raise ClientError({"Error": {"Code": "LoadBalancerNotFound", "Message": "gone"}},
                          "DescribeLoadBalancers")

    def __getattr__(self, name):
        def call(**_kwargs):
            self.calls.append(name)
            return {}
        return call


class FakeEc2:
    def __init__(self):
        self.calls = []

    def describe_security_groups(self, **_kwargs):
        return {"SecurityGroups": [
            {"GroupId": "sg-alb", "GroupName": "enclavize-alb"},
            {"GroupId": "sg-app", "GroupName": "enclavize-app"},
        ]}

    def delete_security_group(self, GroupId):
        self.calls.append(("delete_security_group", GroupId))


class FrontDoorSession:
    def __init__(self, elbv2, ec2):
        self.elbv2, self.ec2 = elbv2, ec2

    def client(self, name, **_kwargs):
        return {"elbv2": self.elbv2, "ec2": self.ec2}.get(name, Unreachable())


def front_door_torn_down():
    elbv2, ec2 = FakeElbv2(), FakeEc2()
    dismantle.delete_front_door(FrontDoorSession(elbv2, ec2), )
    return elbv2.calls, ec2.calls


def test_the_listeners_go_before_the_balancer_and_the_groups_after_it():
    """A target group is refused while a listener forwards to it, and the
    balancer holds its security group until it has actually gone."""
    elb_calls, _ = front_door_torn_down()
    assert elb_calls.index("delete_listener") < elb_calls.index("delete_load_balancer")
    assert elb_calls.count("delete_listener") == 2
    assert elb_calls.index("delete_load_balancer") < elb_calls.index("describe_load_balancers")
    assert elb_calls.index("describe_load_balancers") < elb_calls.index("delete_target_group")
    assert elb_calls.count("delete_target_group") == 2


def test_the_instances_group_goes_before_the_balancers():
    # The instances' group names the balancer's, so it has to let go first.
    _, ec2_calls = front_door_torn_down()
    assert ec2_calls == [("delete_security_group", "sg-app"), ("delete_security_group", "sg-alb")]


def test_a_front_door_left_standing_is_not_a_clean_account():
    standing = leftovers(FrontDoorSession(FakeElbv2(), FakeEc2()), "123456789012", PROFILE)
    assert "load balancer enclavize-app" in standing
    assert "target group enclavize-app-0123abcd" in standing
    assert "security group enclavize-alb" in standing
    assert "load balancer theirs" not in standing


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
        def call(**_kwargs):
            self.journal.append((self.service, name))
            return Nothing()
        return call


class PermissiveSession:
    def __init__(self):
        self.journal = []

    def client(self, name, **_kwargs):
        return Permissive(self.journal, name)


def test_everything_runs_in_the_order_the_dependencies_allow():
    session = PermissiveSession()
    dismantle.everything(session, "123456789012", PROFILE.domain)
    first = {}
    for position, call in enumerate(session.journal):
        first.setdefault(call, position)

    # The front door after the instances (which hold its group), before the
    # certificates (which its listener holds).
    assert first[("ec2", "describe_instances")] < first[("elbv2", "describe_load_balancers")]
    assert first[("elbv2", "describe_load_balancers")] < first[("apigateway", "get_base_path_mappings")]
    assert first[("stepfunctions", "list_state_machines")] < first[("scheduler", "list_schedules")]
    assert first[("scheduler", "list_schedules")] < first[("cloudfront", "list_distributions")]
    assert first[("elbv2", "describe_load_balancers")] < first[("acm", "list_certificates")]
    # The parameters last of all, the go flag among them.
    assert first[("acm", "list_certificates")] < first[("ssm", "delete_parameter")]
