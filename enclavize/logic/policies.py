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


SCHEDULER_SERVICE = "scheduler.amazonaws.com"


def scheduler_trust(*, account_id: str, region: str) -> dict:
    """Assumable by EventBridge Scheduler, and only on this account's behalf.

    Both conditions are the service's own guard against being used as a
    confused deputy: without them a schedule in any account that named this
    role's ARN could have it assumed. The source has to be the schedule group
    rather than a schedule — Scheduler evaluates the condition against the
    group, and a schedule-shaped ARN never matches.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": SCHEDULER_SERVICE},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "aws:SourceArn": f"arn:aws:scheduler:{region}:{account_id}:schedule-group/default",
                    }
                },
            }
        ],
    }


def apply_scheduler_role_policy(*, region: str, account_id: str, switch_state_machine: str) -> dict:
    """Start the switch, and nothing else. What the schedule fires."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "states:StartExecution",
                "Resource": f"arn:aws:states:{region}:{account_id}:stateMachine:{switch_state_machine}",
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

    That absence is also why the bucket itself is named alongside its contents.
    The two phases run in parallel with no channel between them, so this identity
    has to poll for the bucket to appear before it can upload; HeadBucket needs
    s3:ListBucket, and without it S3 answers 403 whether the bucket is missing,
    forbidden or simply not yet made.
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
                "Sid": "WaitForTheBucket",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{proof_bucket}",
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


def apply_machinery_denial(*, region: str, account_id: str, state_machine: str,
                           switch_state_machine: str, domain: str, protected=None) -> dict:
    """Keep applications off the enclave's own API, workflows and distributions.

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
        # All of these names are fixed, so they are known from the start —
        # unlike the API's generated id. Taking the custom domain would let an
        # application answer at apply.{domain} in the enclave's place,
        # collecting the API key out of the header of every request meant for
        # the real one; taking either workflow would let it switch versions on
        # its own terms.
        f"arn:aws:states:{region}:{account_id}:stateMachine:{state_machine}",
        f"arn:aws:states:{region}:{account_id}:execution:{state_machine}:*",
        f"arn:aws:states:{region}:{account_id}:stateMachine:{switch_state_machine}",
        f"arn:aws:states:{region}:{account_id}:execution:{switch_state_machine}:*",
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


PARAMETER_READS = [
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "ssm:GetParameterHistory",
    "ssm:DescribeParameters",
]
"""What an applied commit may do to the enclave's parameters: read them. The
two under apply/ are how it learns what is serving and what is coming."""

ENCLAVE_EC2_ACTIONS = [
    "ec2:TerminateInstances",
    "ec2:StopInstances",
    "ec2:RebootInstances",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:RevokeSecurityGroupIngress",
    "ec2:RevokeSecurityGroupEgress",
    "ec2:ModifySecurityGroupRules",
    "ec2:DeleteSecurityGroup",
    "ec2:CreateTags",
    "ec2:DeleteTags",
]
"""What the boundary denies on anything EC2 tagged with the enclave's name: the
instances a switch is between, and the two groups that decide who may reach
them. Terminating the other version — old or incoming — is the switch's job and
nobody else's; and the tag itself stays put, because it is how the switch and
the teardown find what to retire."""


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
    switch_state_machine: str,
    parameter_path: str,
    protected=None,
) -> dict:
    """The ceiling for everything an applied commit creates.

    An applied commit gets broad power to build whatever the application needs,
    but the enclave's own machinery is fenced off, and — critically — the
    boundary cannot be removed or swapped, so a principal the apply role creates
    can never exceed it.

    `parameter_path` is the Parameter Store path everything of the enclave's
    sits under (`/enclavize/`), which an application may read and not write.
    """
    iam_arn = f"arn:aws:iam::{account_id}"
    boundary_arn = f"{iam_arn}:policy/{resource_prefix}apply-boundary"
    enclave_iam = [
        f"{iam_arn}:role/{resource_prefix}*",
        f"{iam_arn}:user/{resource_prefix}*",
        f"{iam_arn}:policy/{resource_prefix}*",
        f"{iam_arn}:instance-profile/{resource_prefix}*",
    ]
    elb_arn = f"arn:aws:elasticloadbalancing:{region}:{account_id}"
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
                # The apex is the application's apart from five record types:
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
                #   A, AAAA — the apex is where the load balancer answers, and
                #         the load balancer is what makes a switch happen only
                #         once the new version is healthy. Pointed anywhere
                #         else, the application would be serving around it.
                #
                # TXT, SRV, CNAME and the rest at the apex stay the
                # application's.
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
                        "route53:ChangeResourceRecordSetsRecordTypes": [
                            "MX", "NS", "SOA", "A", "AAAA",
                        ],
                    }
                },
            },
            apply_machinery_denial(
                region=region,
                account_id=account_id,
                state_machine=state_machine,
                switch_state_machine=switch_state_machine,
                domain=domain,
                protected=protected,
            ),
            {
                # The front door and everything behind it: the balancer, its
                # listeners, and every target group a switch makes. All named
                # for the enclave, so all known from the start. An application
                # may run balancers of its own; it may not touch this one.
                "Sid": "CannotTouchTheFrontDoor",
                "Effect": "Deny",
                "Action": "elasticloadbalancing:*",
                "Resource": [
                    f"{elb_arn}:loadbalancer/app/{resource_prefix}*/*",
                    f"{elb_arn}:listener/app/{resource_prefix}*/*/*",
                    f"{elb_arn}:listener-rule/app/{resource_prefix}*/*/*/*",
                    f"{elb_arn}:targetgroup/{resource_prefix}*/*",
                ],
            },
            {
                # The one-time schedule that starts a delayed switch. Deleting
                # it would cancel a pending apply; rewriting it would move one.
                "Sid": "CannotTouchTheSwitchTimer",
                "Effect": "Deny",
                "Action": "scheduler:*",
                "Resource": f"arn:aws:scheduler:{region}:{account_id}:schedule/default/{resource_prefix}*",
            },
            {
                # Read-only on the enclave's parameters. NotAction, so every
                # write there is denied without listing each one: the two under
                # apply/ are the account's word on what is serving and what is
                # coming, and an application that could rewrite them could
                # tell itself anything.
                "Sid": "CanOnlyReadTheEnclavesParameters",
                "Effect": "Deny",
                "NotAction": PARAMETER_READS,
                "Resource": f"arn:aws:ssm:{region}:{account_id}:parameter{parameter_path}*",
            },
            {
                # Anything EC2 that carries the enclave's name: the instances a
                # switch is between, and the groups that decide who reaches
                # them. Matched by tag because these are made on the fly and
                # have no fixed ARN.
                "Sid": "CannotTouchTheEnclavesInstancesOrGroups",
                "Effect": "Deny",
                "Action": ENCLAVE_EC2_ACTIONS,
                "Resource": "*",
                "Condition": {
                    "StringLike": {"aws:ResourceTag/Name": f"{resource_prefix}*"}
                },
            },
            {
                # The tag rule above is only as good as the tag, so the name
                # itself is reserved: nothing an application creates may wear
                # it, and nothing may be renamed into it.
                "Sid": "CannotWearTheEnclavesName",
                "Effect": "Deny",
                "Action": "ec2:CreateTags",
                "Resource": "*",
                "Condition": {
                    "StringLike": {"aws:RequestTag/Name": f"{resource_prefix}*"}
                },
            },
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


def apply_state_machine_policy(*, region: str, account_id: str, resource_prefix: str,
                               dashboard_bucket: str, switch_state_machine: str, schedule: str,
                               scheduler_role: str, instance_name_tag: str,
                               parameter_path: str) -> dict:
    """What the two apply workflows may do, shared between them.

    Receiving: read the parameters, look for a switch in flight, start one or
    schedule one. Switching: launch an instance, put it behind the balancer,
    take the previous one out, and keep the parameters and the dashboard's
    record straight. Every resource is named by the enclave's prefix, and the
    one power that could reach an application's own instance — terminating —
    is held to instances wearing the enclave's name.

    The listing is the part worth explaining. The dashboard is a static page and
    cannot list a bucket, so the index it reads has to be written by whatever
    runs on each apply — and that index is rebuilt from a listing rather than
    appended to, which is what makes it heal itself rather than drift. Held to
    the one prefix it reads, so this is no view of the rest of the bucket.
    """
    elb_arn = f"arn:aws:elasticloadbalancing:{region}:{account_id}"
    switch_arn = f"arn:aws:states:{region}:{account_id}:stateMachine:{switch_state_machine}"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:RunInstances", "ec2:CreateTags", "ec2:DescribeInstances"],
                "Resource": "*",
            },
            {
                "Sid": "RetireOnlyTheEnclavesOwn",
                "Effect": "Allow",
                "Action": "ec2:TerminateInstances",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:ResourceTag/Name": instance_name_tag}},
            },
            {
                # Describe calls take no resource, so they stand apart from the
                # writes, which are held to the enclave's own groups and listener.
                "Effect": "Allow",
                "Action": [
                    "elasticloadbalancing:DescribeTargetHealth",
                    "elasticloadbalancing:DescribeTargetGroups",
                    "elasticloadbalancing:DescribeListeners",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "elasticloadbalancing:CreateTargetGroup",
                    "elasticloadbalancing:DeleteTargetGroup",
                    "elasticloadbalancing:ModifyTargetGroupAttributes",
                    "elasticloadbalancing:RegisterTargets",
                    "elasticloadbalancing:DeregisterTargets",
                    "elasticloadbalancing:ModifyListener",
                    "elasticloadbalancing:AddTags",
                ],
                "Resource": [
                    f"{elb_arn}:targetgroup/{resource_prefix}*/*",
                    f"{elb_arn}:listener/app/{resource_prefix}*/*/*",
                ],
            },
            {
                "Effect": "Allow",
                "Action": ["ssm:GetParameter", "ssm:PutParameter", "ssm:DeleteParameter"],
                "Resource": f"arn:aws:ssm:{region}:{account_id}:parameter{parameter_path}apply/*",
            },
            {
                # The receiving workflow's view of the switching one: is one
                # running, and start one.
                "Effect": "Allow",
                "Action": ["states:StartExecution", "states:ListExecutions"],
                "Resource": switch_arn,
            },
            {
                "Effect": "Allow",
                "Action": ["scheduler:CreateSchedule", "scheduler:GetSchedule"],
                "Resource": f"arn:aws:scheduler:{region}:{account_id}:schedule/default/{schedule}",
            },
            {
                # The schedule carries the role Scheduler will assume to start
                # the switch, and creating one means passing it. Held to that
                # service, so the same grant cannot hand the role to anything
                # else.
                "Sid": "PassTheTimerItsRole",
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": f"arn:aws:iam::{account_id}:role/{scheduler_role}",
                "Condition": {"StringEquals": {"iam:PassedToService": SCHEDULER_SERVICE}},
            },
            {
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": [
                    # The record of each apply, and the month shards indexing
                    # them, which sit below the same prefix.
                    f"arn:aws:s3:::{dashboard_bucket}/{naming.APPLIES_PREFIX}*",
                    f"arn:aws:s3:::{dashboard_bucket}/{naming.APPLIES_MANIFEST_KEY}",
                ],
            },
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{dashboard_bucket}",
                "Condition": {
                    "StringLike": {"s3:prefix": f"{naming.APPLIES_PREFIX}*"}
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
