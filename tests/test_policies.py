"""The permission boundary is the fence around the enclave, so it is asserted as
data here and exercised against real IAM in tests/aws/test_iam.py."""

from constants import ACCOUNT_ID, GO_PARAM, REGION

from enclavize.logic import policies

PREFIX = "enclavize-"
PROOF_BUCKET = "enclavize-proof-123456789012"
DASHBOARD_BUCKET = "enclavize-dashboard-123456789012"
BOUNDARY_ARN = f"arn:aws:iam::{ACCOUNT_ID}:policy/{PREFIX}apply-boundary"


ZONE_ID = "Z1EXAMPLE"
DOMAIN = "example.com"
STATE_MACHINE = "enclavize-apply"


def boundary(protected=None):
    return policies.apply_boundary_policy(
        account_id=ACCOUNT_ID,
        region=REGION,
        resource_prefix=PREFIX,
        proof_bucket=PROOF_BUCKET,
        dashboard_bucket=DASHBOARD_BUCKET,
        domain=DOMAIN,
        hosted_zone_id=ZONE_ID,
        state_machine=STATE_MACHINE,
        protected=protected,
    )


def statements(document, effect=None):
    found = document["Statement"]
    if effect:
        found = [s for s in found if s["Effect"] == effect]
    return found


def actions_denied(document):
    denied = set()
    for statement in statements(document, "Deny"):
        action = statement["Action"]
        denied.update([action] if isinstance(action, str) else action)
    return denied


def test_starter_can_only_fire_one_parameter_and_write_one_bucket():
    document = policies.starter_policy(
        region=REGION, account_id=ACCOUNT_ID, go_param=GO_PARAM, proof_bucket=PROOF_BUCKET
    )
    granted = {(s["Action"], s["Resource"]) for s in document["Statement"]}
    assert granted == {
        ("ssm:PutParameter", f"arn:aws:ssm:{REGION}:{ACCOUNT_ID}:parameter/test/go-flag"),
        ("s3:PutObject", f"arn:aws:s3:::{PROOF_BUCKET}/*"),
    }


def test_starter_cannot_delete_what_it_wrote():
    # Proof is append-only from this identity's point of view; immutability then
    # comes from deleting the identity once the objects have landed.
    document = policies.starter_policy(
        region=REGION, account_id=ACCOUNT_ID, go_param=GO_PARAM, proof_bucket=PROOF_BUCKET
    )
    text = str(document)
    assert "Delete" not in text
    assert "s3:*" not in text


def test_event_reader_can_read_history_and_nothing_else():
    document = policies.event_reader_policy()
    assert statements(document, "Deny") == []
    actions = set(document["Statement"][0]["Action"])
    # DescribeRegions is needed to sweep every region for stray activity.
    assert actions == {"cloudtrail:LookupEvents", "ec2:DescribeRegions"}


def test_boundary_grants_broad_app_power():
    allow = statements(boundary(), "Allow")
    assert len(allow) == 1
    assert allow[0]["Action"] == "*"


def test_boundary_fences_off_enclave_identities():
    denied = [s for s in statements(boundary(), "Deny") if s["Sid"] == "CannotTouchEnclaveIdentities"]
    assert denied[0]["Action"] == "iam:*"
    resources = denied[0]["Resource"]
    assert f"arn:aws:iam::{ACCOUNT_ID}:role/{PREFIX}*" in resources
    assert f"arn:aws:iam::{ACCOUNT_ID}:user/{PREFIX}*" in resources
    assert f"arn:aws:iam::{ACCOUNT_ID}:policy/{PREFIX}*" in resources


def test_boundary_blocks_unlocking_the_console_and_moving_the_domain():
    denied = actions_denied(boundary())
    assert "signin:*" in denied
    assert "route53domains:*" in denied


def test_boundary_protects_proof_and_dashboard_buckets():
    denied = [s for s in statements(boundary(), "Deny") if s["Sid"] == "CannotTouchProofOrDashboard"]
    resources = denied[0]["Resource"]
    assert f"arn:aws:s3:::{PROOF_BUCKET}/*" in resources
    assert f"arn:aws:s3:::{DASHBOARD_BUCKET}/*" in resources
    # The buckets themselves too, not just their contents.
    assert f"arn:aws:s3:::{PROOF_BUCKET}" in resources


def test_boundary_protects_the_apply_machinery_from_itself():
    denied = actions_denied(boundary())
    assert {"apigateway:*", "states:*", "cloudfront:*"} <= denied


def test_boundary_cannot_be_removed():
    denied = actions_denied(boundary())
    assert "iam:DeleteRolePermissionsBoundary" in denied
    assert "iam:DeleteUserPermissionsBoundary" in denied


def test_boundary_cannot_be_swapped_for_a_weaker_one():
    swap = [s for s in statements(boundary(), "Deny") if s["Sid"] == "CannotSwapTheBoundaryForAnother"]
    condition = swap[0]["Condition"]["StringNotEquals"]["iam:PermissionsBoundary"]
    assert condition == BOUNDARY_ARN


def test_the_boundary_itself_forces_every_new_principal_to_carry_it():
    """This is what makes the fence hold at any depth.

    In the apply role's own policy alone it would hold for one hop: a role the
    apply created could then mint an unbounded one, and that principal would be
    outside the enclave entirely. In the boundary, every principal carrying it
    inherits the rule.
    """
    minted = [s for s in statements(boundary(), "Deny")
              if s["Sid"] == "EveryPrincipalMintedHereKeepsTheBoundary"]
    assert set(minted[0]["Action"]) == {"iam:CreateRole", "iam:CreateUser"}
    assert minted[0]["Condition"]["StringNotEquals"]["iam:PermissionsBoundary"] == BOUNDARY_ARN


def test_the_apply_role_repeats_the_rule_as_defence_in_depth():
    document = policies.apply_role_policy(boundary_arn=BOUNDARY_ARN)
    denied = [s for s in statements(document, "Deny") if s["Sid"] == "OnlyMintBoundedPrincipals"]
    assert set(denied[0]["Action"]) == {"iam:CreateRole", "iam:CreateUser"}
    assert denied[0]["Condition"]["StringNotEquals"]["iam:PermissionsBoundary"] == BOUNDARY_ARN


def test_the_apply_role_grants_nothing_by_itself():
    # The grant is AdministratorAccess attached separately; this document only
    # constrains, so an edit here can never widen the role.
    document = policies.apply_role_policy(boundary_arn=BOUNDARY_ARN)
    assert statements(document, "Allow") == []


def test_pass_role_is_limited_to_the_apply_role():
    # Otherwise an applied commit could hand itself the admin role and step outside.
    document = policies.pass_role_policy(account_id=ACCOUNT_ID, role_name="enclavize-apply")
    assert document["Statement"][0]["Resource"] == f"arn:aws:iam::{ACCOUNT_ID}:role/enclavize-apply"


def test_cloudfront_bucket_policy_is_allow_only():
    """An explicit Deny here would race the workflow's still-in-flight upload."""
    document = policies.cloudfront_read_bucket_policy(
        bucket=PROOF_BUCKET, distribution_arn="arn:aws:cloudfront::1:distribution/E1"
    )
    assert statements(document, "Deny") == []
    statement = document["Statement"][0]
    assert statement["Action"] == "s3:GetObject"
    assert statement["Condition"]["StringEquals"]["AWS:SourceArn"] == "arn:aws:cloudfront::1:distribution/E1"


def test_ec2_trust_only_trusts_ec2():
    assert policies.EC2_TRUST["Statement"][0]["Principal"] == {"Service": "ec2.amazonaws.com"}
    assert policies.EC2_TRUST["Statement"][0]["Action"] == "sts:AssumeRole"


# --- the enclave's DNS records --------------------------------------------


def test_the_enclaves_own_names_are_fully_protected():
    """Repointing proof.{domain} would serve a forged statement under the
    enclave's own name, and repointing apply.{domain} would collect the API key
    out of every request meant for the real endpoint."""
    denied = [s for s in statements(boundary(), "Deny")
              if s["Sid"] == "CannotTouchTheEnclavesOwnNames"]
    assert denied[0]["Action"] == "route53:ChangeResourceRecordSets"
    assert denied[0]["Resource"] == f"arn:aws:route53:::hostedzone/{ZONE_ID}"
    names = denied[0]["Condition"]["ForAnyValue:StringEquals"][
        "route53:ChangeResourceRecordSetsNormalizedRecordNames"
    ]
    assert set(names) == {f"dashboard.{DOMAIN}", f"proof.{DOMAIN}", f"apply.{DOMAIN}"}
    # The apex is not here: it belongs to the application apart from its MX.
    assert DOMAIN not in names


def test_the_apex_control_records_are_protected():
    """MX reopens the password-reset path; NS hands resolution of every name in
    the domain — proof.{domain} included — to whoever the application picks."""
    denied = [s for s in statements(boundary(), "Deny")
              if s["Sid"] == "CannotTouchTheApexControlRecords"]
    condition = denied[0]["Condition"]["ForAnyValue:StringEquals"]
    assert condition["route53:ChangeResourceRecordSetsNormalizedRecordNames"] == [DOMAIN]
    assert set(condition["route53:ChangeResourceRecordSetsRecordTypes"]) == {"MX", "NS", "SOA"}


def test_an_application_can_use_the_apex_for_its_own_records():
    apex = [s for s in statements(boundary(), "Deny")
            if s["Sid"] == "CannotTouchTheApexControlRecords"][0]
    types = apex["Condition"]["ForAnyValue:StringEquals"][
        "route53:ChangeResourceRecordSetsRecordTypes"
    ]
    for allowed in ("A", "AAAA", "TXT", "SRV", "CNAME"):
        assert allowed not in types


def test_the_boundary_does_not_defend_the_mirrors_uptime():
    """CAA stops the certificate renewing, and so does deleting the ACM
    validation records — but neither makes the statement false. The
    authoritative copy is the attestation at GitHub; proof.{domain} mirrors it.
    """
    apex = [s for s in statements(boundary(), "Deny")
            if s["Sid"] == "CannotTouchTheApexControlRecords"][0]
    types = apex["Condition"]["ForAnyValue:StringEquals"][
        "route53:ChangeResourceRecordSetsRecordTypes"
    ]
    assert "CAA" not in types
    # DNSSEC is DNS hardening, not a property the statement rests on.
    assert not any("DNSSEC" in a for a in actions_denied(boundary()))


def test_protected_record_names_are_normalised():
    # The condition key is matched against lowercase names with no trailing dot.
    document = policies.apply_boundary_policy(
        account_id=ACCOUNT_ID, region=REGION, resource_prefix=PREFIX,
        proof_bucket=PROOF_BUCKET, dashboard_bucket=DASHBOARD_BUCKET,
        domain="Example.COM.", hosted_zone_id=ZONE_ID, state_machine=STATE_MACHINE,
    )
    for sid in ("CannotTouchTheEnclavesOwnNames", "CannotTouchTheApexControlRecords"):
        denied = [s for s in statements(document, "Deny") if s["Sid"] == sid][0]
        names = denied["Condition"]["ForAnyValue:StringEquals"][
            "route53:ChangeResourceRecordSetsNormalizedRecordNames"
        ]
        assert all(n == n.lower() and not n.endswith(".") for n in names), names


# --- what the boundary deliberately leaves alone -------------------------


def test_the_boundary_does_not_bother_with_account_contacts():
    """The path it would defend runs through AWS Support's identity
    verification, which is not documented and so cannot be reasoned about; and
    account:* would also block EnableRegion, which an application may need."""
    assert "account:*" not in actions_denied(boundary())


def test_the_boundary_does_not_bother_with_organizations():
    """A member account has a different account id and no control of this
    domain, so it is outside what the statement claims."""
    assert "organizations:*" not in actions_denied(boundary())


def test_the_boundary_does_not_pretend_to_protect_cloudtrail():
    """The account has no trail — the audit reads Event history, which cannot be
    switched off — and the audit is over before anything can be applied."""
    denied = actions_denied(boundary())
    assert not any(a.startswith("cloudtrail:") for a in denied)


# --- scoping the machinery denial -----------------------------------------


def test_the_machinery_denial_starts_service_wide():
    # Before the API and distributions exist there are no ARNs to name, and the
    # stricter form is the safe one to start from.
    denied = [s for s in statements(boundary(), "Deny")
              if s["Sid"] == "CannotRewriteTheApplyMachinery"]
    assert denied[0]["Resource"] == "*"


def test_the_machinery_denial_narrows_to_named_resources():
    """Denying the whole service also stops the application from ever having an
    API, a workflow or a distribution of its own."""
    document = boundary(protected={"api_id": "abc123", "distribution_ids": ["E1", "E2"]})
    denied = [s for s in statements(document, "Deny")
              if s["Sid"] == "CannotRewriteTheApplyMachinery"]
    resources = denied[0]["Resource"]

    assert resources != "*"
    assert f"arn:aws:states:{REGION}:{ACCOUNT_ID}:stateMachine:{STATE_MACHINE}" in resources
    assert f"arn:aws:apigateway:{REGION}::/restapis/abc123" in resources
    assert f"arn:aws:cloudfront::{ACCOUNT_ID}:distribution/E1" in resources
    assert f"arn:aws:cloudfront::{ACCOUNT_ID}:distribution/E2" in resources


def test_the_narrowed_boundary_still_holds_the_apply_endpoints_name():
    """Taking the custom domain would let an application answer at
    apply.{domain} in the enclave's place, reading the API key out of the header
    of every request meant for the real one. Unlike the API's generated id, the
    name is known from the start, so narrowing must not drop it."""
    document = boundary(protected={"api_id": "abc123", "distribution_ids": ["E1"]})
    denied = [s for s in statements(document, "Deny")
              if s["Sid"] == "CannotRewriteTheApplyMachinery"]
    resources = denied[0]["Resource"]
    assert f"arn:aws:apigateway:{REGION}::/domainnames/apply.{DOMAIN}" in resources
    # And its base path mappings, which are where an API is swapped underneath.
    assert f"arn:aws:apigateway:{REGION}::/domainnames/apply.{DOMAIN}/*" in resources


def test_a_narrowed_boundary_leaves_other_resources_of_those_services_alone():
    document = boundary(protected={"api_id": "abc123", "distribution_ids": ["E1"]})
    denied = [s for s in statements(document, "Deny")
              if s["Sid"] == "CannotRewriteTheApplyMachinery"]
    # An application's own API is not named, so it is not denied.
    assert not any("otherapi" in r for r in denied[0]["Resource"])
    # Nor its own custom domains.
    assert not any(f"/domainnames/www.{DOMAIN}" in r for r in denied[0]["Resource"])
