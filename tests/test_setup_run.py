"""The bring-up sequence.

Two orderings here are load-bearing and neither is obvious from reading the
code in isolation: the proof bucket must be created before anything slow,
because the workflow is blocked waiting for it; and the dashboard must exist
before the apply machinery, because it is the only progress signal an operator
has.
"""

import json
import re

import pytest
from constants import ACCOUNT_ID, APP_REPO, DOMAIN, REGION

from setup import __main__ as bringup
from setup import config, dashboard, proof


class FakeSession:
    def __init__(self, journal):
        self.journal = journal

    def client(self, name, region_name=None):
        return f"client:{name}"


@pytest.fixture
def journal(monkeypatch):
    events = []

    monkeypatch.setattr(bringup.clients, "session", lambda region=None: FakeSession(events))
    monkeypatch.setattr(bringup.sts, "account_id", lambda client: ACCOUNT_ID)

    def step(name, result=None):
        def recorder(*args, **kwargs):
            events.append(name)
            return result

        return recorder

    monkeypatch.setattr(bringup.proof, "create_bucket", step("proof_bucket", f"enclavize-proof-{ACCOUNT_ID}"))
    monkeypatch.setattr(bringup.dns, "create_hosted_zone", step("hosted_zone", ("Z1", ["ns-1"])))
    monkeypatch.setattr(bringup.domains, "update_nameservers_and_wait", step("update_ns"))
    monkeypatch.setattr(bringup.dns, "change_records", step("records", "/change/1"))
    monkeypatch.setattr(bringup.dns, "await_change", step("await_change", True))
    monkeypatch.setattr(bringup.dns, "null_mx_change", lambda d: {"mx": d})
    monkeypatch.setattr(bringup.dns, "upsert", lambda *a, **k: {})
    monkeypatch.setattr(bringup.acm, "request_certificate", step("cert_request", "arn:cert"))
    monkeypatch.setattr(bringup.acm, "validation_records", step("cert_records", []))
    monkeypatch.setattr(bringup.acm, "await_issued", step("cert_issued"))
    monkeypatch.setattr(bringup.dashboard, "create_bucket", step("dashboard_bucket", "b"))
    monkeypatch.setattr(bringup.dashboard, "attach_cdn", step("dashboard_cdn", {"id": "E1"}))
    monkeypatch.setattr(bringup.dashboard, "mark", step("dashboard_mark"))
    monkeypatch.setattr(bringup.cdn, "await_deployed", step("cdn_deployed", True))
    monkeypatch.setattr(bringup.apply, "create_roles", step("apply_roles", {
        "boundary_arn": "arn:b", "sfn_role_arn": "arn:sfn", "api_role_arn": "arn:api",
    }))
    monkeypatch.setattr(bringup.apply, "create_state_machine", step("apply_sfn", "arn:sm"))
    monkeypatch.setattr(bringup.apply, "create_api", step("apply_api", ("https://x/v1/commits", "api1")))
    monkeypatch.setattr(bringup.apply, "attach_custom_domain",
                        step("apply_domain", "https://apply.example.com/v1/commits"))
    monkeypatch.setattr(bringup.apply, "tighten_boundary", step("tighten_boundary"))
    monkeypatch.setattr(bringup.proof, "attach_cdn", step("proof_cdn", {"id": "E2"}))
    monkeypatch.setattr(bringup.proof, "await_and_seal", step("proof_seal", True))
    return events


def run(**overrides):
    kwargs = dict(domain=DOMAIN, app_repo=APP_REPO, api_key="k" * 32, region=REGION, log=lambda *_: None)
    kwargs.update(overrides)
    return bringup.run(**kwargs)


def test_nothing_cheap_sits_behind_the_certificate(journal):
    """The certificate is the only thing gating visibility, so everything that
    needs no waiting happens before it starts."""
    run()
    cert = journal.index("cert_issued")
    for instant in ("proof_bucket", "dashboard_bucket", "hosted_zone", "cert_request"):
        assert journal.index(instant) < cert, instant


def test_the_proof_bucket_is_created_first_of_all(journal):
    """The workflow is already polling for it, and cannot do anything else."""
    run()
    assert journal[0] == "proof_bucket"


def test_the_dashboard_content_is_ready_long_before_it_can_be_served(journal):
    # Static files, so filling the bucket has nothing to do with the certificate.
    run()
    assert journal.index("dashboard_bucket") < journal.index("cert_issued")
    assert journal.index("dashboard_cdn") > journal.index("cert_issued")


def test_the_certificate_is_requested_before_the_delegation_moves(journal):
    """The request needs no delegation; only validation does. Publishing the
    records first lets ACM pass the moment the delegation lands."""
    run()
    assert journal.index("cert_request") < journal.index("update_ns")
    assert journal.index("cert_records") < journal.index("update_ns")


def test_the_registrar_is_pointed_at_the_new_zone_before_the_certificate_issues(journal):
    # Validation cannot succeed until that delegation has propagated.
    run()
    assert journal.index("update_ns") < journal.index("cert_issued")


def test_the_apply_machinery_is_built_during_the_certificate_wait(journal):
    """It needs only the account and the bucket names, so waiting for a
    certificate first would waste its whole duration."""
    run()
    cert = journal.index("cert_issued")
    for step_name in ("apply_roles", "apply_sfn", "apply_api"):
        assert journal.index(step_name) < cert, step_name


def test_the_state_it_reports_is_not_cached_like_the_rest():
    """status.json is rewritten as the bring-up moves. Cached like the static
    page beside it, the one window into the account would answer with a state
    the bring-up left behind hours earlier."""
    recorded = {}

    class Recorder:
        def put_object(self, **kwargs):
            recorded.update(kwargs)

    dashboard.mark(Recorder(), bucket="b", domain=DOMAIN, app_repo=APP_REPO, state="complete")
    assert recorded["Key"] == config.STATUS_KEY
    assert recorded["CacheControl"] == config.CHANGES_CACHE_CONTROL


def test_the_apply_endpoint_waits_for_the_certificate(journal):
    """A custom domain is rejected without one. This is why the API itself is
    built during the certificate wait but its public name is not."""
    run()
    assert journal.index("apply_api") < journal.index("cert_issued")
    assert journal.index("cert_issued") < journal.index("apply_domain")


def test_both_distributions_are_created_before_either_is_awaited(journal):
    """Serially this costs each distribution's ten-odd minutes in turn."""
    run()
    last_created = max(journal.index("dashboard_cdn"), journal.index("proof_cdn"))
    assert journal.index("cdn_deployed") > last_created


def test_both_distributions_are_actually_awaited(journal):
    # The old flow claimed the proof site was serving without ever waiting.
    run()
    assert journal.count("cdn_deployed") == 2


def test_the_mailbox_is_killed_before_the_account_starts_serving(journal):
    run()
    assert journal.index("records") < journal.index("apply_api")


def test_proof_is_sealed_only_after_the_apply_path_exists(journal):
    # Retiring the starter user is the last thing; nothing after it could
    # publish if it failed.
    run()
    assert journal.index("proof_seal") == len(journal) - 2  # followed only by the final mark
    assert journal.index("apply_api") < journal.index("proof_seal")


def test_the_full_order(journal):
    run()
    assert journal == [
        # nothing here waits on anything
        "proof_bucket",
        "dashboard_bucket",
        "hosted_zone",
        "records",          # null MX, fired and not awaited
        "cert_request",
        "cert_records",
        "records",          # the validation records
        # hand over the domain, then fill the wait with work that does not need
        # the certificate
        "update_ns",
        "apply_roles",
        "apply_sfn",
        "apply_api",
        "dashboard_mark",
        "cert_issued",
        # everything the certificate was blocking
        "apply_domain",
        "dashboard_cdn",
        "proof_cdn",
        "cdn_deployed",
        "cdn_deployed",
        "tighten_boundary",
        "proof_seal",
        "dashboard_mark",
    ]


def test_a_missing_proof_is_reported_rather_than_hidden(journal, monkeypatch):
    marks = []
    monkeypatch.setattr(bringup.proof, "await_and_seal", lambda *a, **k: False)
    monkeypatch.setattr(
        bringup.dashboard, "mark",
        lambda client, *, bucket, domain, app_repo, state, proof="pending":
            marks.append((state, proof)),
    )

    result = run()

    assert result["proof_published"] is False
    assert ("complete", "missing") in marks


# --- the static site ------------------------------------------------------


def test_the_site_is_a_folder_of_plain_files():
    """No build step: what is in the repo is what is served."""
    keys = [key for key, _ in dashboard.asset_files()]
    assert "index.html" in keys
    assert "style.css" in keys
    assert "app.js" in keys


def test_nothing_in_the_site_needs_building():
    # No bundler manifests, no sources that have to be compiled first.
    keys = [key for key, _ in dashboard.asset_files()]
    assert not any(key.endswith((".jsx", ".ts", ".tsx", ".scss")) for key in keys)
    assert not any(key in ("package.json", "package-lock.json") for key in keys)


def asset(name):
    return (dashboard.ASSETS / name).read_text(encoding="utf-8")


def test_the_site_loads_nothing_from_another_host():
    """Not a ban on naming other hosts — a ban on loading from them.

    A page with no third-party subresources is one nobody outside can watch
    being read, and one no third party can restyle into saying something else.
    The typeface has to travel with the page for the same reason.
    """
    page, css, script = asset("index.html"), asset("style.css"), asset("app.js")

    assert "@import" not in css
    for attribute in ("src=", "href="):
        for fragment in page.split(attribute)[1:]:
            assert fragment.lstrip("\"'").startswith("./"), fragment[:60]
    for fragment in css.split("url(")[1:]:
        assert fragment.lstrip("\"'").startswith("./"), fragment[:60]
    for fetched in re.findall(r"""read\(\s*["'`]([^"'`]*)""", script):
        assert fetched.startswith("./"), fetched

    assert "@font-face" in css
    assert any(path.suffix == ".woff2" for _, path in dashboard.asset_files())


def test_the_only_other_host_is_one_a_person_clicks():
    """github.com is named, and only ever as somewhere a link goes.

    A link costs nothing until it is followed, opens in its own tab so this page
    stays where it was, and carries rel=noreferrer so following one does not
    tell GitHub which sealed account it came from.
    """
    script = asset("app.js")
    offsite = [line.strip() for line in script.splitlines()
               if "https://" in line and not line.lstrip().startswith("//")]

    assert offsite
    for line in offsite:
        assert line.startswith(("commit.href =", "repo.href =")), line
        assert "https://github.com/" in line
    assert script.count('target = "_blank"') == len(offsite)
    assert script.count('rel = "noreferrer"') == len(offsite)


def test_every_asset_gets_a_content_type_that_will_actually_render():
    # S3 serves whatever it is told; a wrong type breaks the page silently.
    assert dashboard.content_type_for("index.html").startswith("text/html")
    assert dashboard.content_type_for("style.css").startswith("text/css")
    assert dashboard.content_type_for("app.js").startswith("text/javascript")
    assert dashboard.content_type_for("status.json") == "application/json"
    assert dashboard.content_type_for("mystery.bin") == "application/octet-stream"


def test_assets_keep_their_layout_when_uploaded(tmp_path):
    nested = tmp_path / "img"
    nested.mkdir()
    (tmp_path / "index.html").write_text("<!doctype html>", encoding="utf-8")
    (nested / "logo.svg").write_text("<svg/>", encoding="utf-8")

    keys = [key for key, _ in dashboard.asset_files(tmp_path)]

    assert keys == ["img/logo.svg", "index.html"]


def test_uploading_puts_every_file_in_the_bucket():
    put = []

    class Recorder:
        def put_object(self, **kwargs):
            put.append((kwargs["Key"], kwargs["ContentType"]))

    uploaded = dashboard.upload_assets(Recorder(), bucket="b")

    assert set(uploaded) == {key for key, _ in dashboard.asset_files()}
    assert ("index.html", "text/html; charset=utf-8") in put
    assert ("app.js", "text/javascript; charset=utf-8") in put


def test_the_status_is_machine_readable_so_it_can_be_polled():
    status = json.loads(dashboard.render_status(
        domain=DOMAIN, app_repo=APP_REPO, state="complete", proof="published"))
    assert status == {"domain": DOMAIN, "appRepo": APP_REPO,
                      "state": "complete", "proof": "published"}


def test_the_status_carries_what_the_page_cannot_know_by_itself():
    """The page is uploaded verbatim, so neither the domain nor the repo it is
    bound to can be baked into it. Which repo a domain answers to is not visible
    from outside a sealed account any other way."""
    status = json.loads(dashboard.render_status(
        domain=DOMAIN, app_repo=APP_REPO, state="starting"))
    assert status["domain"] == DOMAIN
    assert status["appRepo"] == APP_REPO


def test_the_page_reads_everything_it_shows_from_its_own_bucket():
    script = asset("app.js")
    assert '"./status.json"' in script
    assert f'"./{config.APPLIES_MANIFEST_KEY}"' in script


def test_the_page_has_somewhere_to_put_each_field():
    page = asset("index.html")
    for element in ('id="domain"', 'id="state"', 'id="repo"', 'id="applies"'):
        assert element in page


# --- self-termination -----------------------------------------------------


def test_the_instance_destroys_itself_even_when_the_bring_up_fails(monkeypatch):
    """A failed bring-up must not leave a box holding administrator credentials."""
    terminated = []
    monkeypatch.setattr(bringup, "run", lambda **_: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(bringup, "instance_id", lambda: "i-self")
    monkeypatch.setattr(bringup.clients, "session", lambda region=None: FakeSession([]))
    monkeypatch.setattr(bringup.ec2, "terminate", lambda client, iid: terminated.append(iid))
    monkeypatch.setenv("ENCLAVIZE_DOMAIN", DOMAIN)
    monkeypatch.setenv("ENCLAVIZE_APP_REPO", APP_REPO)
    monkeypatch.setenv("ENCLAVIZE_APPLY_API_KEY", "k")

    with pytest.raises(RuntimeError, match="boom"):
        bringup.main()

    assert terminated == ["i-self"]


def test_a_failure_to_self_terminate_does_not_mask_the_real_error(monkeypatch, capsys):
    monkeypatch.setattr(bringup, "run", lambda **_: (_ for _ in ()).throw(RuntimeError("original")))
    monkeypatch.setattr(bringup, "instance_id", lambda: (_ for _ in ()).throw(OSError("no imds")))
    monkeypatch.setenv("ENCLAVIZE_DOMAIN", DOMAIN)
    monkeypatch.setenv("ENCLAVIZE_APP_REPO", APP_REPO)
    monkeypatch.setenv("ENCLAVIZE_APPLY_API_KEY", "k")

    with pytest.raises(RuntimeError, match="original"):
        bringup.main()

    assert "could not self-terminate" in capsys.readouterr().out


def test_a_missing_setting_is_named(monkeypatch):
    monkeypatch.delenv("ENCLAVIZE_DOMAIN", raising=False)
    with pytest.raises(SystemExit, match="ENCLAVIZE_DOMAIN"):
        bringup.env("ENCLAVIZE_DOMAIN")
