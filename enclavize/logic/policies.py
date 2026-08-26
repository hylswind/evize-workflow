"""IAM policy documents, as data.

These are pure functions returning dicts so the security-critical shapes can be
asserted offline. The AWS layer only ships them.

The identities enclavize leaves behind are deliberately narrow:
- event reader: can read history and enumerate regions, nothing else.
- starter: can fire one SSM parameter and write proof objects to one bucket. It
  is the only credential that outlives the root key, and the setup program
  deletes it once the proof has landed.
- console: billing, plus metadata about what exists. ViewOnlyAccess is List and
  Describe, so this identity can see that a bucket or a table is there and
  cannot read a single object, secret or row out of it.
- admin role: full power, assumable only by EC2 — used by the setup instance and
  then left dormant, since the apply boundary forbids passing it.
"""

from enclavize.logic import naming

ADMIN_MANAGED_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
BILLING_MANAGED_POLICY = "arn:aws:iam::aws:policy/job-function/Billing"
VIEW_ONLY_MANAGED_POLICY = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"

EC2_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def service_trust(service: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def event_reader_policy() -> dict:
    """Read history, and list regions so the check can sweep all of them."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["cloudtrail:LookupEvents", "ec2:DescribeRegions"],
                "Resource": "*",
            }
        ],
    }


def starter_policy(*, region: str, account_id: str, go_param: str, proof_bucket: str) -> dict:
    """One parameter to write, one bucket to put into. No deletes anywhere.

    The proof bucket does not exist yet when this policy is created — the setup
    program makes it later — which IAM permits: a policy may name an ARN that
    has not been created.
    """
    param_name = go_param.lstrip("/")
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "FireTheGoFlag",
                "Effect": "Allow",
                "Action": "ssm:PutParameter",
                "Resource": f"arn:aws:ssm:{region}:{account_id}:parameter/{param_name}",
            },
            {
                "Sid": "WriteProofOnce",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{proof_bucket}/*",
            },
        ],
    }


def console_self_service_policy(*, account_id: str) -> dict:
    """Enough for the human to change their own password, and no more.

    The resource has to be a full ARN with ${aws:username} substituted into it.
    A bare "${aws:username}" is not an ARN and IAM rejects the whole document.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:ChangePassword", "iam:GetUser"],
                "Resource": f"arn:aws:iam::{account_id}:user/${{aws:username}}",
            },
            {
                "Effect": "Allow",
                "Action": "iam:GetAccountPasswordPolicy",
                "Resource": "*",
            },
        ],
    }


def apply_machinery_denial(*, region: str, account_id: str, state_machine: str, domain: str,
                           protected=None) -> dict:
    """Keep applications off the enclave's own API, workflow and distributions.

    Named resources where they are known, and the whole service where they are
    not. The distinction matters: denying `apigateway:*` outright also stops the
    application from ever having an API of its own, which is collateral rather
    than intent. `protected` carries the ARNs that only exist once the machinery
    has been built, so the boundary is created service-wide and narrowed in
    place afterwards — tightening late is safe, since nothing can be applied
    until setup has finished.
    """
    protected = protected or {}
    api_id = protected.get("api_id")
    distributions = protected.get("distribution_ids") or []

    if not api_id and not distributions:
        return {
            "Sid": "CannotRewriteTheApplyMachinery",
            "Effect": "Deny",
            "Action": ["apigateway:*", "states:*", "cloudfront:*"],
            "Resource": "*",
        }

    apply_host = naming.apply_host(domain)
    resources = [
        # Both names are fixed, so these are known from the start — unlike the
        # API's generated id. Taking the custom domain would let an application
        # answer at apply.{domain} in the enclave's place, collecting the API
        # key out of the header of every request meant for the real one.
        f"arn:aws:states:{region}:{account_id}:stateMachine:{state_machine}",
        f"arn:aws:states:{region}:{account_id}:execution:{state_machine}:*",
        f"arn:aws:apigateway:{region}::/domainnames/{apply_host}",
        f"arn:aws:apigateway:{region}::/domainnames/{apply_host}/*",
    ]
    if api_id:
        resources += [
            f"arn:aws:apigateway:{region}::/restapis/{api_id}",
            f"arn:aws:apigateway:{region}::/restapis/{api_id}/*",
        ]
    resources += [
        f"arn:aws:cloudfront::{account_id}:distribution/{did}" for did in distributions
    ]
    return {
        "Sid": "CannotRewriteTheApplyMachinery",
        "Effect": "Deny",
        "Action": ["apigateway:*", "states:*", "cloudfront:*"],
        "Resource": resources,
    }


def apply_boundary_policy(
    *,
    account_id: str,
    region: str,
    resource_prefix: str,
    proof_bucket: str,
    dashboard_bucket: str,
    domain: str,
    hosted_zone_id: str,
    state_machine: str,
    protected=None,
) -> dict:
    """The ceiling for everything an applied commit creates.

    An applied commit gets broad power to build whatever the application needs,
    but the enclave's own machinery is fenced off, and — critically — the
    boundary cannot be removed or swapped, so a principal the apply role creates
    can never exceed it.
    """
    iam_arn = f"arn:aws:iam::{account_id}"
    boundary_arn = f"{iam_arn}:policy/{resource_prefix}apply-boundary"
    enclave_iam = [
        f"{iam_arn}:role/{resource_prefix}*",
        f"{iam_arn}:user/{resource_prefix}*",
        f"{iam_arn}:policy/{resource_prefix}*",
        f"{iam_arn}:instance-profile/{resource_prefix}*",
    ]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AppPowerUpToThisCeiling",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
            {
                "Sid": "CannotTouchEnclaveIdentities",
                "Effect": "Deny",
                "Action": "iam:*",
                "Resource": enclave_iam,
            },
            {
                "Sid": "CannotUnlockTheConsole",
                "Effect": "Deny",
                "Action": "signin:*",
                "Resource": "*",
            },
            {
                "Sid": "CannotMoveTheDomain",
                "Effect": "Deny",
                "Action": "route53domains:*",
                "Resource": "*",
            },
            {
                "Sid": "CannotTouchProofOrDashboard",
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{proof_bucket}",
                    f"arn:aws:s3:::{proof_bucket}/*",
                    f"arn:aws:s3:::{dashboard_bucket}",
                    f"arn:aws:s3:::{dashboard_bucket}/*",
                ],
            },
            {
                # These three names are the enclave's own. Repointing proof.
                # would serve a statement of the application's choosing under
                # the enclave's name; dashboard. is the only window into the
                # account; and apply. is the way in, so redirecting it would
                # hand every apply request — API key header and all — to
                # whatever answered instead. Everything else in the zone is the
                # application's.
                "Sid": "CannotTouchTheEnclavesOwnNames",
                "Effect": "Deny",
                "Action": "route53:ChangeResourceRecordSets",
                "Resource": f"arn:aws:route53:::hostedzone/{hosted_zone_id}",
                "Condition": {
                    "ForAnyValue:StringEquals": {
                        # Lowercase, no trailing dot, as the key is normalised.
                        "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
                            naming.dashboard_host(domain).lower().rstrip("."),
                            naming.proof_host(domain).lower().rstrip("."),
                            naming.apply_host(domain).lower().rstrip("."),
                        ]
                    }
                },
            },
            {
                # The apex is the application's apart from three record types,
                # each of which could make the signed statement untrue:
                #
                #   MX  — the null MX is what killed the mailbox; restoring it
                #         reopens the account's password-reset path.
                #   NS  — repointing the apex nameservers hands resolution of
                #         every name in the domain to whoever the application
                #         chooses, including proof.{domain}. The alias record
                #         being protected does not help if the resolver never
                #         reaches this zone.
                #   SOA — the zone's own parameters; grouped with NS as the
                #         delegation's foundation.
                #
                # A, AAAA, TXT and the rest at the apex stay the application's.
                #
                # Deliberately absent: CAA, which would stop the certificate
                # renewing, and with it the ACM validation records elsewhere in
                # the zone. Both take the sites down without making the
                # statement false — the authoritative copy is the attestation
                # at GitHub, and proof.{domain} only mirrors it. This boundary
                # defends the statement's truth, not the mirror's uptime.
                "Sid": "CannotTouchTheApexControlRecords",
                "Effect": "Deny",
                "Action": "route53:ChangeResourceRecordSets",
                "Resource": f"arn:aws:route53:::hostedzone/{hosted_zone_id}",
                "Condition": {
                    "ForAnyValue:StringEquals": {
                        "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
                            domain.lower().rstrip("."),
                        ],
                        "route53:ChangeResourceRecordSetsRecordTypes": ["MX", "NS", "SOA"],
                    }
                },
            },
            apply_machinery_denial(
                region=region,
                account_id=account_id,
                state_machine=state_machine,
                domain=domain,
                protected=protected,
            ),
            {
                # The rule that makes the fence hold at any depth. It lives in
                # the boundary rather than in the apply role's own policy so
                # that every principal carrying the boundary inherits it: a role
                # an applied commit creates can only create further principals
                # that also carry it. In the role's policy alone this would hold
                # for one hop, and the principal created there could mint an
                # unbounded one.
                "Sid": "EveryPrincipalMintedHereKeepsTheBoundary",
                "Effect": "Deny",
                "Action": ["iam:CreateRole", "iam:CreateUser"],
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {"iam:PermissionsBoundary": boundary_arn}
                },
            },
            {
                "Sid": "CannotEscapeTheBoundary",
                "Effect": "Deny",
                "Action": [
                    "iam:DeleteRolePermissionsBoundary",
                    "iam:DeleteUserPermissionsBoundary",
                ],
                "Resource": "*",
            },
            {
                "Sid": "CannotSwapTheBoundaryForAnother",
                "Effect": "Deny",
                "Action": [
                    "iam:PutRolePermissionsBoundary",
                    "iam:PutUserPermissionsBoundary",
                ],
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {"iam:PermissionsBoundary": boundary_arn}
                },
            },
        ],
    }


def apply_role_policy(*, boundary_arn: str) -> dict:
    """Defence in depth, and nothing else.

    The grant is AdministratorAccess, attached as a managed policy — identical
    to an inline "Allow *:*" and clearer about the intent: this role asks for
    everything, and every limit on it comes from the boundary.

    This one statement repeats a rule the boundary already carries, so that a
    single edit to the boundary cannot open even the first hop.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "OnlyMintBoundedPrincipals",
                "Effect": "Deny",
                "Action": ["iam:CreateRole", "iam:CreateUser"],
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {"iam:PermissionsBoundary": boundary_arn}
                },
            },
        ],
    }


def pass_role_policy(*, account_id: str, role_name: str) -> dict:
    """Allow passing exactly one role — the apply instance role."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": f"arn:aws:iam::{account_id}:role/{role_name}",
            }
        ],
    }


def cloudfront_read_bucket_policy(*, bucket: str, distribution_arn: str) -> dict:
    """Let one distribution read the bucket, via origin access control.

    Allow-only on purpose: an explicit Deny here would race the workflow's proof
    upload, which may still be in flight when the distribution is attached. The
    guarantee that nobody can rewrite proof comes from deleting the starter user
    afterwards, not from this document.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCloudFrontRead",
                "Effect": "Allow",
                "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"AWS:SourceArn": distribution_arn}},
            }
        ],
    }
