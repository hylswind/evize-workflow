"""enclavize/aws/elbv2.py against real AWS.

Two things only a real account answers: how long a balancer takes to become
active and to go away — the bring-up and the teardown each wait on one — and
whether a balancer across every default subnet, behind a group it names, is
accepted at all. Everything created here carries the run's prefix and is
removed in the order the dependencies allow.
"""

import time

import pytest
from botocore.exceptions import ClientError

from enclavize.aws import ec2 as ec2mod
from enclavize.aws import elbv2 as elbmod
from setup import config as setup_config

pytestmark = pytest.mark.aws

ACTIVE_BUDGET = setup_config.LB_ACTIVE_POLL_MAX_SECONDS
DELETE_BUDGET = 600


@pytest.fixture
def front_door(ec2, elbv2, prefix):
    """Two groups and a balancer, torn down listeners → balancer → groups."""
    res = setup_config.RESOURCES.with_prefix(prefix)
    vpc_id = ec2mod.default_vpc(ec2)
    lb_sg = ec2mod.create_security_group(ec2, name=res.app_lb_sg, description="test", vpc_id=vpc_id)
    app_sg = ec2mod.create_security_group(ec2, name=res.app_sg, description="test", vpc_id=vpc_id)
    made = {"res": res, "vpc_id": vpc_id, "lb_sg": lb_sg, "app_sg": app_sg, "balancer": None,
            "groups": []}
    yield made
    try:
        balancer = made["balancer"]
        if balancer:
            for listener in elbmod.listeners(elbv2, balancer["arn"]):
                elbmod.delete_listener(elbv2, listener)
            elbmod.delete_load_balancer(elbv2, balancer["arn"])
            elbmod.await_deleted(elbv2, balancer["arn"], poll_max=DELETE_BUDGET, interval=10)
        for group in made["groups"]:
            elbmod.delete_target_group(elbv2, group)
    finally:
        for group_id in (app_sg, lb_sg):
            for _ in range(12):
                try:
                    ec2mod.delete_security_group(ec2, group_id)
                    break
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") != "DependencyViolation":
                        break
                    time.sleep(10)


def test_a_balancer_across_the_default_subnets_becomes_active(ec2, elbv2, front_door):
    res = front_door["res"]
    ec2mod.authorize_ingress(ec2, group_id=front_door["lb_sg"], port=80)
    ec2mod.authorize_ingress(ec2, group_id=front_door["app_sg"], port=80,
                             source_group_id=front_door["lb_sg"])

    started = time.monotonic()
    balancer = elbmod.create_load_balancer(
        elbv2, name=res.app_lb, subnets=ec2mod.default_subnets(ec2, front_door["vpc_id"]),
        security_groups=[front_door["lb_sg"]],
    )
    front_door["balancer"] = balancer
    elbmod.create_redirect_listener(elbv2, load_balancer_arn=balancer["arn"])

    assert elbmod.await_active(elbv2, balancer["arn"], poll_max=ACTIVE_BUDGET, interval=10)
    waited = time.monotonic() - started
    # Recorded so the configured window can be judged against reality.
    print(f"active after {waited:.0f}s of a {ACTIVE_BUDGET}s budget")
    assert balancer["dns_name"].endswith(".amazonaws.com")
    assert balancer["zone_id"]
    assert [b["name"] for b in elbmod.load_balancers_named(elbv2, res.prefix)] == [res.app_lb]


def test_a_target_group_is_checked_only_once_a_listener_names_it(ec2, elbv2, front_door):
    """What the switch machine's ordering rests on: a group no listener points
    at is `unused`, never `unhealthy` and never `healthy`."""
    res = front_door["res"]
    balancer = elbmod.create_load_balancer(
        elbv2, name=res.app_lb, subnets=ec2mod.default_subnets(ec2, front_door["vpc_id"]),
        security_groups=[front_door["lb_sg"]],
    )
    front_door["balancer"] = balancer
    group = elbv2.create_target_group(
        Name=f"{res.prefix}app-test", Protocol="HTTP", Port=80, VpcId=front_door["vpc_id"],
        TargetType="instance", HealthCheckPath=setup_config.HEALTH_PATH,
    )["TargetGroups"][0]["TargetGroupArn"]
    front_door["groups"].append(group)

    health = elbv2.describe_target_health(TargetGroupArn=group)["TargetHealthDescriptions"]
    # Nothing registered: nothing to describe, and the group is not in use.
    assert health == []
    assert [g["name"] for g in elbmod.target_groups_named(elbv2, res.prefix)] == [f"{res.prefix}app-test"]
