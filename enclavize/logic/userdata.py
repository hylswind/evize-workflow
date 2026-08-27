"""Build the user-data for the setup instance: the account's own bring-up.

It clones enclavize itself at the sha the reusable workflow was pinned to, then
holds until the go flag appears before running. The wait sits here rather than
inside the setup program so that the program's first instruction cannot run
before the account is sealed. There is no shell contract between this script and
the program: both are enclavize, so it invokes the module directly.

An apply instance's user-data is not built here. The state machine renders it
instead, so the commit can be substituted by States.Format with no Lambda in the
path — and one script with two authors is one script too many.

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
