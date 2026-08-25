"""User-data is shell text built from untrusted-ish values, and it carries a
secret. The quoting and the trace boundary are what these tests defend."""

from constants import APP_REPO, DOMAIN, GO_PARAM, REGION, SELF_REPO, SELF_SHA

from enclavize.logic import userdata

API_KEY = "super-secret-key"


def setup_script(**overrides):
    kwargs = dict(
        self_repo=SELF_REPO,
        self_sha=SELF_SHA,
        region=REGION,
        domain=DOMAIN,
        app_repo=APP_REPO,
        deploy_api_key=API_KEY,
        go_param=GO_PARAM,
    )
    kwargs.update(overrides)
    return userdata.build_setup_userdata(**kwargs)


def test_setup_clones_enclavize_at_the_pinned_sha():
    # The instance must run the code the attestation covers, not a branch tip.
    script = setup_script()
    assert f"git clone https://github.com/{SELF_REPO}.git" in script
    assert f"git checkout {SELF_SHA}" in script


def test_setup_stops_tracing_before_exporting_the_api_key():
    # Console output is readable by anyone who can call EC2, and set -x would
    # echo the secret into it.
    script = setup_script()
    assert script.index("set +x") < script.index("ENCLAVIZE_DEPLOY_API_KEY")


def test_setup_waits_for_the_go_flag_before_running_anything():
    # The account is not sealed until the flag lands, so the program's first
    # instruction must sit after the wait.
    script = setup_script()
    assert script.index(f"aws ssm get-parameter --name {GO_PARAM}") < script.index("exec python3 -m setup")


def test_setup_invokes_the_module_directly_with_no_shell_contract():
    # setup.sh is the deploy-time contract with an app repo; enclavize's own
    # bring-up needs no such indirection.
    script = setup_script()
    assert "exec python3 -m setup" in script
    assert "setup.sh" not in script


def test_setup_quotes_every_interpolated_value():
    script = setup_script(domain="evil'; rm -rf /; echo '")
    # The injected quote is escaped rather than terminating the assignment.
    assert "rm -rf /" in script  # present as data...
    for line in script.splitlines():
        if line.startswith("export ENCLAVIZE_DOMAIN="):
            value = line.split("=", 1)[1]
            assert value.startswith("'") and value.endswith("'")
            # ...and cannot escape its quoting
            assert "'\"'\"'" in value
            break
    else:
        raise AssertionError("no domain export found")


def test_setup_installs_what_it_needs_to_run_python():
    script = setup_script()
    assert "dnf install -y git python3 python3-pip" in script
    assert "pip3 install -r requirements.txt" in script


def test_deploy_clones_the_app_repo_and_runs_its_entrypoint():
    commit = "b" * 40
    script = userdata.build_deploy_userdata(
        app_repo=APP_REPO, commit=commit, region=REGION, domain=DOMAIN
    )
    assert f"git clone https://github.com/{APP_REPO}.git" in script
    assert f"git checkout {commit}" in script
    assert "exec ./setup.sh" in script


def test_deploy_does_not_carry_the_api_key():
    # A deploy instance has no business holding the key that triggers deploys.
    script = userdata.build_deploy_userdata(
        app_repo=APP_REPO, commit="c" * 40, region=REGION, domain=DOMAIN
    )
    assert "DEPLOY_API_KEY" not in script


def test_both_scripts_fail_fast():
    scripts = [
        setup_script(),
        userdata.build_deploy_userdata(app_repo=APP_REPO, commit="d" * 40, region=REGION, domain=DOMAIN),
    ]
    for script in scripts:
        assert script.startswith("#!/bin/bash\nset -euxo pipefail")
