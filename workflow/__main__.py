"""Phase A: seal the account, then sign a statement saying so.

Ordering is the security property here. Everything reversible happens first, so
a bad password or an unreachable GitHub fails while the account is still usable.
Only then does the run take the two irreversible steps — closing the console and
deleting root's key — and it launches the setup instance immediately before
them, because that launch is the last thing root is needed for.

The run then audits itself with a second identity, hands the account over, and
writes the statement the workflow signs.
"""

import datetime
import json
import os
import sys

from enclavize.aws import sts
from enclavize.logic import github, naming, statement as statement_logic, userdata

from . import clients, config, credentials
from .steps import (
    s1_identities,
    s2_launch,
    s3_domain_transfer,
    s4_lock_signin,
    s5_delete_root,
    s6_hold,
    s7_event_check,
    s8_handover,
)


class RunConfig:
    """Everything the run needs, validated before any of it is used."""

    def __init__(self, **values):
        self.__dict__.update(values)

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env

        def required(name):
            value = env.get(name)
            if not value:
                raise ValueError(f"enclavize: {name} is required")
            return value

        def flag(name):
            return str(env.get(name, "")).strip().lower() in ("1", "true", "yes")

        start_raw = required("ENCLAVIZE_START")
        try:
            start = int(start_raw)
        except ValueError:
            raise ValueError(f"enclavize: ENCLAVIZE_START {start_raw!r} is not a unix timestamp") from None
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        if start >= now:
            raise ValueError("enclavize: ENCLAVIZE_START must be in the past")

        domain = required("ENCLAVIZE_DOMAIN").strip().lower()
        if "." not in domain or " " in domain:
            raise ValueError(f"enclavize: ENCLAVIZE_DOMAIN {domain!r} is not a domain")

        # The reusable workflow has to discover itself: inside one,
        # github.repository names the caller, not enclavize.
        self_repo, _ = github.parse_job_workflow_ref(required("ENCLAVIZE_SELF_REF"))
        self_sha = github.require_sha(required("ENCLAVIZE_SELF_SHA"))

        return cls(
            root_key=required("ENCLAVIZE_ROOT_KEY"),
            root_secret=required("ENCLAVIZE_ROOT_SECRET"),
            transfer_password=env.get("ENCLAVIZE_TRANSFER_PASSWORD", ""),
            apply_api_key=required("ENCLAVIZE_APPLY_API_KEY"),
            domain=domain,
            start=start,
            app_repo=github.require_repo(required("ENCLAVIZE_REPO")),
            self_repo=self_repo,
            self_sha=self_sha,
            caller_repo=env.get("ENCLAVIZE_CALLER_REPO", ""),
            gh_token=env.get("ENCLAVIZE_GH_TOKEN") or None,
            bypass_event_check=flag("ENCLAVIZE_BYPASS_EVENT_CHECK"),
            bypass_domain_transfer=flag("ENCLAVIZE_BYPASS_DOMAIN_TRANSFER"),
            region=env.get("ENCLAVIZE_REGION", config.REGION),
        )

    @property
    def bypasses(self):
        return statement_logic.build_bypasses(
            event_check=self.bypass_event_check,
            domain_transfer=self.bypass_domain_transfer,
        )


def run(cfg, *, res=None, log=print):
    res = res or config.RESOURCES

    # Every request id the run issues, so the audit can tell its own calls from
    # a person's rather than inferring it from what the events look like.
    own_request_ids = set()

    # Before anything touches the account: a bad pin should not cost a seal.
    repo_id = github.resolve_repo_id(cfg.app_repo, token=cfg.gh_token)
    log(f"app repo {cfg.app_repo} is id {repo_id}")

    root = clients.session(cfg.root_key, cfg.root_secret, region=cfg.region, record=own_request_ids)
    # Everything from here on is the workflow's own doing; the audit splits the
    # history here and holds this side to request-id attribution.
    workflow_started_at = datetime.datetime.now(datetime.timezone.utc)
    account_id = sts.account_id(root.client("sts"))
    log(f"account {account_id}")

    identities = s1_identities.create_identities(
        root.client("iam"), res=res, region=cfg.region, account_id=account_id
    )
    log("identities created")

    # Written immediately: a failure further down still owes the operator a way
    # to see their own account.
    credentials.write_console_credentials(
        config.CONSOLE_FILE,
        credentials.build_console_credentials(
            account_id=account_id,
            user_name=res.console_user,
            password=identities["console_password"],
            domain=cfg.domain,
        ),
    )
    log(f"wrote {config.CONSOLE_FILE}")

    if cfg.bypass_domain_transfer:
        log("bypass: not accepting a domain transfer")
    else:
        s3_domain_transfer.accept(
            root.client("route53domains"),
            domain=cfg.domain,
            password=cfg.transfer_password,
            poll_max=config.TRANSFER_POLL_MAX_SECONDS,
            interval=config.TRANSFER_POLL_INTERVAL,
        )
        log(f"domain {cfg.domain} transferred in")

    # --- past here the account cannot be handed back ---

    vpc_id, statement_id = s4_lock_signin.lock(
        root.client("ec2"), root.client("signin"),
        res=res, account_id=account_id, region=cfg.region,
    )
    log(f"console locked (anchor {vpc_id}, statement {statement_id})")

    instance_id = s2_launch.launch(
        root.client("ec2"), root.client("ssm"),
        res=res,
        user_data=userdata.build_setup_userdata(
            self_repo=cfg.self_repo,
            self_sha=cfg.self_sha,
            region=cfg.region,
            domain=cfg.domain,
            app_repo=cfg.app_repo,
            apply_api_key=cfg.apply_api_key,
            go_param=res.go_param,
        ),
        ami_param=config.BASE_AMI_PARAM,
        instance_type=config.INSTANCE_TYPE,
        wait_seconds=config.INSTANCE_PROFILE_WAIT_SECONDS,
        retry_interval=config.INSTANCE_PROFILE_RETRY_INTERVAL,
    )
    log(f"setup instance {instance_id} launched, waiting on the go flag")

    s5_delete_root.delete_root_key(root.client("iam"), cfg.root_key)
    log("root key deleted")

    log(f"holding {config.HOLD_SECONDS}s for history to settle")
    s6_hold.wait(config.HOLD_SECONDS)

    reader = clients.session(identities["reader_key"], identities["reader_secret"], region=cfg.region,
                             record=own_request_ids)
    if cfg.bypass_event_check:
        log("bypass: not checking event history")
    else:
        start = datetime.datetime.fromtimestamp(cfg.start, datetime.timezone.utc)
        end = datetime.datetime.now(datetime.timezone.utc)
        verdict = s7_event_check.verify(
            reader.client("cloudtrail"),
            reader.client("ec2"),
            lambda region: reader.client("cloudtrail", region_name=region),
            start=start,
            end=end,
            home_region=cfg.region,
            poll_max=config.DELIVERY_POLL_MAX_SECONDS,
            interval=config.DELIVERY_POLL_INTERVAL,
            own_request_ids=own_request_ids,
            workflow_started_at=workflow_started_at,
        )
        if not verdict.ok:
            raise SystemExit(verdict.report())
        log("event check passed: only enclavize acted in this account")

    starter = clients.session(identities["starter_key"], identities["starter_secret"], region=cfg.region,
                              record=own_request_ids)
    s8_handover.release(starter.client("ssm"), go_param=res.go_param, value=config.GO_VALUE)
    log("go flag fired; the account is now running itself")

    statement = statement_logic.build_statement(
        account_id=account_id,
        domain=cfg.domain,
        start=cfg.start,
        hold_seconds=config.HOLD_SECONDS,
        repo_id=repo_id,
        bypasses=cfg.bypasses,
    )
    statement_logic.write_statement(config.STATEMENT_FILE, statement)
    log(f"wrote {config.STATEMENT_FILE} (debug={statement['debug']})")

    # Handed to the publish step, which runs after the workflow signs.
    return {
        "account_id": account_id,
        "proof_bucket": naming.proof_bucket_name(account_id),
        "starter_key": identities["starter_key"],
        "starter_secret": identities["starter_secret"],
        "region": cfg.region,
        "statement": statement,
    }


def main(argv=None):
    cfg = RunConfig.from_env()
    result = run(cfg)
    # Publishing has to be a separate process because it can only run once the
    # attestation exists, so the credentials it needs are handed over on disk.
    write_publish_handover(config.HANDOVER_FILE, result)
    return 0


def write_publish_handover(path, result) -> None:
    """Leave the publish step what it needs, and only that.

    A file rather than GITHUB_ENV: anything exported there is readable by every
    later step and by anything that dumps the environment. This file is
    gitignored and never uploaded as an artifact. The mask directive means that
    even an accidental echo of the secret is redacted from the public log.
    """
    print(f"::add-mask::{result['starter_secret']}")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "proofBucket": result["proof_bucket"],
                    "starterKey": result["starter_key"],
                    "starterSecret": result["starter_secret"],
                    "region": result["region"],
                }
            )
            + "\n"
        )
    os.chmod(path, 0o600)


if __name__ == "__main__":
    sys.exit(main())
