"""Zones and records — including the MX record that kills the account's email."""

import boto3
import pytest
from constants import DOMAIN, REGION, clock, no_sleep
from moto import mock_aws

from enclavize.aws import dns


@pytest.fixture
def r53():
    with mock_aws():
        yield boto3.client("route53", region_name=REGION)


def make_zone(r53, domain=DOMAIN):
    return dns.create_hosted_zone(r53, domain=domain, caller_reference="ref-1", comment="test")


def records_of(r53, zone_id, record_type):
    sets = r53.list_resource_record_sets(HostedZoneId=zone_id)["ResourceRecordSets"]
    return [r for r in sets if r["Type"] == record_type]


def test_a_new_zone_reports_its_delegation_set(r53):
    # These nameservers are what the registrar has to be pointed at; a
    # transferred domain never brings its old zone along.
    zone_id, nameservers = make_zone(r53)
    assert zone_id
    assert len(nameservers) >= 2
    assert dns.nameservers(r53, zone_id) == nameservers


def test_null_mx_is_the_rfc_7505_form():
    change = dns.null_mx_change(DOMAIN)
    record = change["ResourceRecordSet"]
    assert record["Type"] == "MX"
    assert change["Action"] == "UPSERT"
    # A single "." exchanger: this domain accepts no mail at all.
    assert record["ResourceRecords"] == [{"Value": "0 ."}]


def test_null_mx_actually_lands_in_the_zone(r53):
    zone_id, _ = make_zone(r53)
    dns.change_records(r53, zone_id=zone_id, changes=[dns.null_mx_change(DOMAIN)])
    mx = records_of(r53, zone_id, "MX")
    assert mx[0]["ResourceRecords"] == [{"Value": "0 ."}]


def test_records_are_upserted_so_a_rerun_is_not_an_error(r53):
    zone_id, _ = make_zone(r53)
    dns.change_records(r53, zone_id=zone_id, changes=[dns.upsert("a." + DOMAIN, "TXT", ['"one"'])])
    dns.change_records(r53, zone_id=zone_id, changes=[dns.upsert("a." + DOMAIN, "TXT", ['"two"'])])
    txt = records_of(r53, zone_id, "TXT")
    assert len(txt) == 1
    assert txt[0]["ResourceRecords"] == [{"Value": '"two"'}]


def test_an_alias_carries_no_ttl_and_names_the_target_zone():
    change = dns.upsert_alias(
        "dashboard." + DOMAIN,
        target_dns="d123.cloudfront.net",
        hosted_zone_id="Z2FDTNDATAQYW2",
    )
    record = change["ResourceRecordSet"]
    assert "TTL" not in record
    assert record["AliasTarget"]["HostedZoneId"] == "Z2FDTNDATAQYW2"
    assert record["AliasTarget"]["DNSName"] == "d123.cloudfront.net"
    assert record["AliasTarget"]["EvaluateTargetHealth"] is False


def test_await_change_returns_once_route53_reports_insync():
    class Change:
        def get_change(self, Id):
            return {"ChangeInfo": {"Status": "INSYNC"}}

    assert dns.await_change(Change(), "/change/1", poll_max=600, interval=15,
                            sleep=no_sleep, now=clock([0, 1]))


def test_await_change_gives_up_without_raising():
    class Pending:
        def get_change(self, Id):
            return {"ChangeInfo": {"Status": "PENDING"}}

    assert dns.await_change(Pending(), "/change/1", poll_max=600, interval=15,
                            sleep=no_sleep, now=clock([0, 5000])) is False


def test_deleting_a_zone_clears_the_records_it_gained(r53):
    zone_id, _ = make_zone(r53)
    dns.change_records(r53, zone_id=zone_id, changes=[dns.null_mx_change(DOMAIN)])

    dns.delete_zone(r53, zone_id)

    remaining = [z["Id"] for z in r53.list_hosted_zones()["HostedZones"]]
    assert not any(zone_id in z for z in remaining)


def test_deleting_a_zone_leaves_its_own_ns_and_soa_alone(r53):
    """Those come with the zone and cannot be deleted separately."""
    zone_id, _ = make_zone(r53)
    deleted = {}

    original = dns.change_records

    def spy(client, *, zone_id, changes, comment=""):
        deleted["changes"] = changes
        return original(client, zone_id=zone_id, changes=changes, comment=comment)

    dns.change_records = spy
    try:
        dns.change_records(r53, zone_id=zone_id, changes=[dns.upsert("x." + DOMAIN, "TXT", ['"v"'])])
        dns.delete_zone(r53, zone_id)
    finally:
        dns.change_records = original

    types = {c["ResourceRecordSet"]["Type"] for c in deleted.get("changes", [])}
    assert "SOA" not in types
    assert "NS" not in types
