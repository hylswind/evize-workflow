"""Hosted zones and records, including the one that kills the account's email.

A transferred domain arrives without its hosted zone, so the account builds a
fresh one and hands its delegation set back to the registrar.
"""

import time

# RFC 7505: a single "." exchanger says this domain accepts no mail at all,
# which is what makes the root user's email address unusable and therefore
# closes the password-reset path back into the account.
NULL_MX = "0 ."


def create_hosted_zone(r53, *, domain: str, caller_reference: str, comment: str = "") -> tuple:
    """Create a public zone. Returns (zone_id, nameservers)."""
    response = r53.create_hosted_zone(
        Name=domain,
        CallerReference=caller_reference,
        HostedZoneConfig={"Comment": comment, "PrivateZone": False},
    )
    zone_id = response["HostedZone"]["Id"].split("/")[-1]
    return zone_id, response["DelegationSet"]["NameServers"]


def nameservers(r53, zone_id: str) -> list:
    return r53.get_hosted_zone(Id=zone_id)["DelegationSet"]["NameServers"]


def change_records(r53, *, zone_id: str, changes: list, comment: str = "") -> str:
    """Apply a change batch. Returns the change id for syncing on."""
    return r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Comment": comment, "Changes": changes},
    )["ChangeInfo"]["Id"]


def upsert(name: str, record_type: str, values, ttl: int = 300) -> dict:
    """An UPSERT change, so re-running a bring-up is not an error."""
    return {
        "Action": "UPSERT",
        "ResourceRecordSet": {
            "Name": name,
            "Type": record_type,
            "TTL": ttl,
            "ResourceRecords": [{"Value": value} for value in values],
        },
    }


def upsert_alias(name: str, *, target_dns: str, hosted_zone_id: str, record_type: str = "A") -> dict:
    """An alias record pointing at a distribution.

    Aliases carry no TTL and need the target's own zone id, which for CloudFront
    is the fixed value Z2FDTNDATAQYW2.
    """
    return {
        "Action": "UPSERT",
        "ResourceRecordSet": {
            "Name": name,
            "Type": record_type,
            "AliasTarget": {
                "HostedZoneId": hosted_zone_id,
                "DNSName": target_dns,
                "EvaluateTargetHealth": False,
            },
        },
    }


def null_mx_change(domain: str) -> dict:
    """The record that makes the account's email address dead."""
    return upsert(domain, "MX", [NULL_MX])


def await_change(r53, change_id: str, *, poll_max: int, interval: int,
                 sleep=time.sleep, now=time.monotonic) -> bool:
    """Wait for a change to reach INSYNC across Route 53. False on timeout."""
    deadline = now() + poll_max
    while True:
        status = r53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return True
        if now() >= deadline:
            return False
        sleep(interval)


def delete_zone(r53, zone_id: str) -> None:
    """Remove every record the zone did not come with, then the zone.

    NS and SOA at the apex are created with the zone and cannot be deleted
    separately.
    """
    paginator = r53.get_paginator("list_resource_record_sets")
    apex = r53.get_hosted_zone(Id=zone_id)["HostedZone"]["Name"]
    changes = []
    for page in paginator.paginate(HostedZoneId=zone_id):
        for record in page["ResourceRecordSets"]:
            if record["Name"] == apex and record["Type"] in ("NS", "SOA"):
                continue
            changes.append({"Action": "DELETE", "ResourceRecordSet": record})
    if changes:
        change_records(r53, zone_id=zone_id, changes=changes, comment="teardown")
    r53.delete_hosted_zone(Id=zone_id)
