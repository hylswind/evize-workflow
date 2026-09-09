"""The front door: what is asked of the load balancer, and the two waits.

moto stores balancers, listeners and target groups, so those round-trip; the
waits are driven through fakes, where the interesting behaviour is timing.
"""

import boto3
import pytest
from constants import REGION, clock, error, no_sleep
from moto import mock_aws

from enclavize.aws import ec2 as ec2mod
from enclavize.aws import elbv2 as elbmod


@pytest.fixture
def clients():
    with mock_aws():
        yield boto3.client("ec2", region_name=REGION), boto3.client("elbv2", region_name=REGION)


def front_door(ec2, elbv2, name="enclavize-app"):
    vpc_id = ec2mod.default_vpc(ec2)
    subnets = ec2mod.default_subnets(ec2, vpc_id)
    sg = ec2mod.create_security_group(ec2, name=f"{name}-sg", description="d", vpc_id=vpc_id)
    return elbmod.create_load_balancer(elbv2, name=name, subnets=subnets, security_groups=[sg])


def test_the_balancer_spans_every_default_subnet_and_faces_the_internet(clients):
    ec2, elbv2 = clients
    made = front_door(ec2, elbv2)

    described = elbv2.describe_load_balancers(LoadBalancerArns=[made["arn"]])["LoadBalancers"][0]
    assert described["Scheme"] == "internet-facing"
    assert described["Type"] == "application"
    zones = {az["SubnetId"] for az in described["AvailabilityZones"]}
    assert zones == set(ec2mod.default_subnets(ec2, ec2mod.default_vpc(ec2)))
    assert len(zones) >= 2
    # What the alias record needs.
    assert made["dns_name"] and made["zone_id"]
    assert {"Key": "Name", "Value": "enclavize-app"} in elbv2.describe_tags(
        ResourceArns=[made["arn"]])["TagDescriptions"][0]["Tags"]


def test_port_80_only_redirects(clients):
    ec2, elbv2 = clients
    made = front_door(ec2, elbv2)
    arn = elbmod.create_redirect_listener(elbv2, load_balancer_arn=made["arn"])

    listener = elbv2.describe_listeners(ListenerArns=[arn])["Listeners"][0]
    assert listener["Port"] == 80
    action = listener["DefaultActions"][0]
    assert action["Type"] == "redirect"
    assert action["RedirectConfig"]["Protocol"] == "HTTPS"
    assert action["RedirectConfig"]["Port"] == "443"
    assert action["RedirectConfig"]["StatusCode"] == "HTTP_301"


def test_port_443_carries_the_certificate_and_answers_nothing_yet():
    """The switch is what first forwards it anywhere; until then it says so."""
    recorded = {}

    class Recorder:
        def create_listener(self, **kwargs):
            recorded.update(kwargs)
            return {"Listeners": [{"ListenerArn": "arn:listener"}]}

    arn = elbmod.create_https_listener(
        Recorder(), load_balancer_arn="arn:lb", certificate_arn="arn:cert",
        status_code=503, body="not yet",
    )
    assert arn == "arn:listener"
    assert recorded["Protocol"] == "HTTPS" and recorded["Port"] == 443
    assert recorded["Certificates"] == [{"CertificateArn": "arn:cert"}]
    assert recorded["SslPolicy"] == elbmod.TLS_POLICY
    assert recorded["DefaultActions"] == [{
        "Type": "fixed-response",
        "FixedResponseConfig": {"StatusCode": "503", "ContentType": "text/plain", "MessageBody": "not yet"},
    }]
    assert not any("TargetGroupArn" in str(a) for a in recorded["DefaultActions"])


def test_balancers_and_groups_are_found_by_prefix(clients):
    ec2, elbv2 = clients
    ours = front_door(ec2, elbv2, name="t1234-app")
    front_door(ec2, elbv2, name="someone-elses")
    vpc_id = ec2mod.default_vpc(ec2)
    elbv2.create_target_group(Name="t1234-app-0123abcd", Protocol="HTTP", Port=80, VpcId=vpc_id)
    elbv2.create_target_group(Name="theirs", Protocol="HTTP", Port=80, VpcId=vpc_id)

    assert [b["arn"] for b in elbmod.load_balancers_named(elbv2, "t1234-")] == [ours["arn"]]
    assert [g["name"] for g in elbmod.target_groups_named(elbv2, "t1234-")] == ["t1234-app-0123abcd"]


class Provisioning:
    def __init__(self, codes):
        self.codes = list(codes)

    def describe_load_balancers(self, **_kwargs):
        code = self.codes.pop(0) if len(self.codes) > 1 else self.codes[0]
        if code == "gone":
            raise error("LoadBalancerNotFound", "DescribeLoadBalancers")
        return {"LoadBalancers": [{"State": {"Code": code}}]}


def test_await_active_waits_out_provisioning():
    assert elbmod.await_active(Provisioning(["provisioning", "provisioning", "active"]), "arn:lb",
                               poll_max=600, interval=15, sleep=no_sleep, now=clock([0, 1, 2, 3]))


def test_await_active_gives_up_without_raising():
    assert elbmod.await_active(Provisioning(["provisioning"]), "arn:lb",
                               poll_max=600, interval=15, sleep=no_sleep,
                               now=clock([0, 99999])) is False


def test_a_balancer_that_failed_to_provision_is_not_waited_for():
    # The apex would otherwise be pointed at nothing, and the wait would only
    # ever time out.
    with pytest.raises(RuntimeError, match="failed to provision"):
        elbmod.await_active(Provisioning(["failed"]), "arn:lb",
                            poll_max=600, interval=15, sleep=no_sleep, now=clock([0, 1]))


def test_await_deleted_returns_once_the_balancer_is_gone():
    """Which is when it releases its security groups — the thing a teardown
    is waiting to delete next."""
    assert elbmod.await_deleted(Provisioning(["active", "active", "gone"]), "arn:lb",
                                poll_max=600, interval=15, sleep=no_sleep, now=clock([0, 1, 2, 3]))
    assert elbmod.await_deleted(Provisioning(["active"]), "arn:lb",
                                poll_max=600, interval=15, sleep=no_sleep,
                                now=clock([0, 99999])) is False


def test_deleting_is_split_the_way_the_dependencies_run(clients):
    ec2, elbv2 = clients
    made = front_door(ec2, elbv2)
    listener = elbmod.create_redirect_listener(elbv2, load_balancer_arn=made["arn"])
    group = elbv2.create_target_group(Name="enclavize-app-1", Protocol="HTTP", Port=80,
                                      VpcId=ec2mod.default_vpc(ec2))["TargetGroups"][0]

    assert elbmod.listeners(elbv2, made["arn"]) == [listener]
    elbmod.delete_listener(elbv2, listener)
    elbmod.delete_load_balancer(elbv2, made["arn"])
    elbmod.delete_target_group(elbv2, group["TargetGroupArn"])

    assert elbmod.load_balancers_named(elbv2, "enclavize-") == []
    assert elbmod.target_groups_named(elbv2, "enclavize-") == []
