"""The load balancer in front of whatever commit is currently applied.

Built once at bring-up and never replaced: the apex record points at it, and a
switch between versions is a change to its listener rather than to DNS. The
target groups behind it are made and removed by the switch state machine, not
here — this module holds only what the bring-up and the teardown call.

A load balancer takes a few minutes to become active and a while to go away,
so both directions have a wait with an injected clock, like the rest of the
AWS layer.
"""

import time

from botocore.exceptions import ClientError

TLS_POLICY = "ELBSecurityPolicy-TLS13-1-2-2021-06"

_ABSENT = ("LoadBalancerNotFound",)


def create_load_balancer(elbv2, *, name: str, subnets, security_groups, tags=None) -> dict:
    """An internet-facing application load balancer across the given subnets.

    Returns what the rest of the bring-up needs: the ARN to hang listeners on,
    and the DNS name plus hosted zone id an alias record has to carry.
    """
    created = elbv2.create_load_balancer(
        Name=name,
        Subnets=list(subnets),
        SecurityGroups=list(security_groups),
        Scheme="internet-facing",
        Type="application",
        IpAddressType="ipv4",
        Tags=[{"Key": key, "Value": value} for key, value in (tags or {"Name": name}).items()],
    )["LoadBalancers"][0]
    return {
        "arn": created["LoadBalancerArn"],
        "dns_name": created["DNSName"],
        "zone_id": created["CanonicalHostedZoneId"],
        "vpc_id": created["VpcId"],
    }


def create_redirect_listener(elbv2, *, load_balancer_arn: str) -> str:
    """Port 80 answers only to send the caller to 443."""
    return elbv2.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[
            {
                "Type": "redirect",
                "RedirectConfig": {
                    "Protocol": "HTTPS",
                    "Port": "443",
                    "Host": "#{host}",
                    "Path": "/#{path}",
                    "Query": "#{query}",
                    "StatusCode": "HTTP_301",
                },
            }
        ],
    )["Listeners"][0]["ListenerArn"]


def create_https_listener(elbv2, *, load_balancer_arn: str, certificate_arn: str,
                          status_code: int, body: str) -> str:
    """Port 443 with the certificate, answering a fixed response until a version
    is switched in. The switch state machine is what replaces this default with
    a forward; nothing here ever names a target group.
    """
    return elbv2.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol="HTTPS",
        Port=443,
        SslPolicy=TLS_POLICY,
        Certificates=[{"CertificateArn": certificate_arn}],
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {
                    "StatusCode": str(status_code),
                    "ContentType": "text/plain",
                    "MessageBody": body,
                },
            }
        ],
    )["Listeners"][0]["ListenerArn"]


def state(elbv2, load_balancer_arn: str) -> str:
    """provisioning, active, active_impaired, failed — or 'gone'."""
    try:
        described = elbv2.describe_load_balancers(LoadBalancerArns=[load_balancer_arn])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in _ABSENT:
            return "gone"
        raise
    return described["LoadBalancers"][0]["State"]["Code"]


def await_active(elbv2, load_balancer_arn: str, *, poll_max: int, interval: int,
                 sleep=time.sleep, now=time.monotonic) -> bool:
    """Wait for the balancer to be routing. False on timeout.

    Raises if it ends `failed`: that is not a wait that will ever finish, and the
    apex would otherwise be pointed at nothing.
    """
    deadline = now() + poll_max
    while True:
        current = state(elbv2, load_balancer_arn)
        if current == "active":
            return True
        if current == "failed":
            raise RuntimeError(f"enclavize: load balancer {load_balancer_arn} failed to provision")
        if now() >= deadline:
            return False
        sleep(interval)


def await_deleted(elbv2, load_balancer_arn: str, *, poll_max: int, interval: int,
                  sleep=time.sleep, now=time.monotonic) -> bool:
    """Wait for a deleted balancer to actually go, which is when it releases
    its security groups. False on timeout."""
    deadline = now() + poll_max
    while True:
        if state(elbv2, load_balancer_arn) == "gone":
            return True
        if now() >= deadline:
            return False
        sleep(interval)


def load_balancers_named(elbv2, prefix: str) -> list:
    """Every balancer whose name carries the prefix, as {arn, name} dicts."""
    found = []
    for page in elbv2.get_paginator("describe_load_balancers").paginate():
        for item in page["LoadBalancers"]:
            if item["LoadBalancerName"].startswith(prefix):
                found.append({"arn": item["LoadBalancerArn"], "name": item["LoadBalancerName"]})
    return found


def target_groups_named(elbv2, prefix: str) -> list:
    """Every target group whose name carries the prefix, as {arn, name} dicts.

    A teardown has to sweep these by prefix: the switch machine makes one per
    attempt, and an attempt that died leaves its group behind.
    """
    found = []
    for page in elbv2.get_paginator("describe_target_groups").paginate():
        for item in page["TargetGroups"]:
            if item["TargetGroupName"].startswith(prefix):
                found.append({"arn": item["TargetGroupArn"], "name": item["TargetGroupName"]})
    return found


def listeners(elbv2, load_balancer_arn: str) -> list:
    return [
        item["ListenerArn"]
        for page in elbv2.get_paginator("describe_listeners").paginate(
            LoadBalancerArn=load_balancer_arn)
        for item in page["Listeners"]
    ]


def delete_listener(elbv2, listener_arn: str) -> None:
    """Its own step: a listener holds the certificate, and a target group is
    refused deletion while any listener still forwards to it."""
    elbv2.delete_listener(ListenerArn=listener_arn)


def delete_load_balancer(elbv2, load_balancer_arn: str) -> None:
    elbv2.delete_load_balancer(LoadBalancerArn=load_balancer_arn)


def delete_target_group(elbv2, target_group_arn: str) -> None:
    elbv2.delete_target_group(TargetGroupArn=target_group_arn)
