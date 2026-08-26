"""Build the user-data for the two kinds of instance enclavize launches.

- setup: the account's own bring-up. Clones enclavize itself at the sha the
  reusable workflow was pinned to, then holds until the go flag appears before
  running. The wait sits here rather than inside the setup program so that the
  program's first instruction cannot run before the account is sealed. There is
  no shell contract between this script and the program: both are enclavize, so
  it invokes the module directly.
- apply: launched later by the apply state machine. Clones the APP repo at a
  commit and runs its setup.sh, which is the one interface enclavize requires of
  an application.

Every interpolated value is single-quoted, and secrets are exported only after
`set +x` so they never reach the console log (get-console-output is readable by
anyone who can call EC2).
"""

_SETUP_TEMPLATE = r"""#!/bin/bash
set -euxo pipefail
dnf install -y git python3 python3-pip
rm -rf /opt/enclavize
git clone https://github.com/{repo}.git /opt/enclavize
cd /opt/enclavize
git checkout {commit}
pip3 install -r requirements.txt
set +x
export AWS_DEFAULT_REGION={region}
export ENCLAVIZE_REGION={region}
export ENCLAVIZE_DOMAIN={domain}
export ENCLAVIZE_APP_REPO={app_repo}
export ENCLAVIZE_APPLY_API_KEY={apply_api_key}
until aws ssm get-parameter --name {go_param} >/dev/null 2>&1; do sleep 30; done
exec python3 -m setup
"""

_APPLY_TEMPLATE = r"""#!/bin/bash
set -euxo pipefail
dnf install -y git
rm -rf /opt/app
git clone https://github.com/{repo}.git /opt/app
cd /opt/app
git checkout {commit}
set +x
export AWS_DEFAULT_REGION={region}
export ENCLAVIZE_REGION={region}
export ENCLAVIZE_DOMAIN={domain}
export ENCLAVIZE_COMMIT={commit}
exec ./{entrypoint}
"""

APP_ENTRYPOINT = "setup.sh"


def _shquote(value: str) -> str:
    """Single-quote a value for safe use in a shell assignment."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def build_setup_userdata(
    *,
    self_repo: str,
    self_sha: str,
    region: str,
    domain: str,
    app_repo: str,
    apply_api_key: str,
    go_param: str,
) -> str:
    """User-data for the instance that brings the sealed account up.

    `self_repo`/`self_sha` are enclavize's own repo and the sha the reusable
    workflow was pinned to, so the code that runs here is the code the
    attestation covers.
    """
    return _SETUP_TEMPLATE.format(
        repo=self_repo,
        commit=self_sha,
        region=region,
        domain=_shquote(domain),
        app_repo=_shquote(app_repo),
        apply_api_key=_shquote(apply_api_key),
        go_param=go_param,
    )


def build_apply_userdata(
    *,
    app_repo: str,
    commit: str,
    region: str,
    domain: str,
    entrypoint: str = APP_ENTRYPOINT,
) -> str:
    """User-data for an apply instance: clone the app at a commit and run it."""
    return _APPLY_TEMPLATE.format(
        repo=app_repo,
        commit=commit,
        region=region,
        domain=_shquote(domain),
        entrypoint=entrypoint,
    )
