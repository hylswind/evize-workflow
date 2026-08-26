"""What the end-to-end run needs to know, and where each piece comes from.

Three sources, and the split is the point:

- **read, not configured** — the caller's own workflow file already says which
  reusable workflow it calls and at what ref. Stripping the `@ref` off its
  `uses:` line gives exactly the value `gh attestation verify --signer-workflow`
  wants, so it is derived rather than typed twice and left to drift.
- **the profile** — everything else that is not a secret. One file per account
  under test, so pointing the suite at a different caller or a different
  application is a matter of choosing a profile.
- **the environment** — gates and secrets only. A secret never enters the
  profile, because profiles are files and files get committed.

Nothing here hardcodes a repository, a domain or an application. Resource names
are imported from the production config rather than retyped, so renaming one
breaks these tests instead of quietly pointing them at something that no longer
exists.
"""

import base64
import json
import os
import pathlib
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

import yaml

# Imported, never retyped. A renamed resource has to break these tests rather
# than leave them asserting against something that no longer exists.
from workflow import config as workflow_config

PREDICATE_TYPE = workflow_config.PREDICATE_TYPE

# PyYAML reads a bare `on:` key as the boolean True (YAML 1.1 truthiness), the
# same quirk tests/test_workflow_yaml.py documents.
ON = True

# What a caller has to expose for this suite to be able to drive it. These are
# enclavize's own input names, so a caller that renames them is not testable
# here — preflight says so rather than letting the dispatch fail obscurely.
REQUIRED_INPUTS = frozenset({
    "domain", "start", "repo", "bypass_event_check", "bypass_domain_transfer",
})
REQUIRED_PERMISSIONS = {
    "id-token": "write",
    "attestations": "write",
    "contents": "read",
}

DEFAULT_TIMEOUTS = {"seal": 3600, "bringup": 5400, "apply": 900}

STATE_FILE = pathlib.Path(__file__).parent / ".e2e-state.json"
"""What stage 1 leaves for the later stages: which run to read the statement
from, and what it was verified against. Gitignored — it names a real account."""


class ProfileError(Exception):
    """The profile or the caller it names cannot be used as given."""


# --- the profile ----------------------------------------------------------


@dataclass(frozen=True)
class App:
    """The application whose commits this account applies.

    Only `repo` is required, because only `repo` is part of enclavize's own
    contract: an application is a repo with an executable setup.sh. The rest
    describe what one particular application happens to do once applied, and
    every stage that uses them skips when they are unset.
    """

    repo: str
    ref: str = ""
    url: str = ""
    results_url: str = ""
    teardown: str = ""


@dataclass(frozen=True)
class Profile:
    caller: str
    domain: str
    app: App
    caller_workflow: str = "enclavize.yml"
    rescue_key_id: str = ""
    transfer: str = "bypass"
    timeouts: dict = field(default_factory=lambda: dict(DEFAULT_TIMEOUTS))

    @property
    def bypass_domain_transfer(self) -> bool:
        return self.transfer == "bypass"

    def timeout(self, name: str) -> int:
        return int(self.timeouts.get(name, DEFAULT_TIMEOUTS[name]))


def load_profile(path) -> Profile:
    """Read a profile file. Raises ProfileError with the field at fault."""
    text = pathlib.Path(path).read_text(encoding="utf-8")
    return parse_profile(text)


def parse_profile(text: str) -> Profile:
    raw = yaml.safe_load(text) or {}
    if not isinstance(raw, dict):
        raise ProfileError("profile must be a mapping")

    for required in ("caller", "domain", "app"):
        if not raw.get(required):
            raise ProfileError(f"profile is missing {required}")

    app_raw = raw["app"]
    if not isinstance(app_raw, dict) or not app_raw.get("repo"):
        raise ProfileError("profile is missing app.repo")

    transfer = str(raw.get("transfer", "bypass"))
    if transfer not in ("bypass", "real"):
        raise ProfileError(f"transfer must be 'bypass' or 'real', not {transfer!r}")

    for name in ("caller", "app.repo"):
        value = raw["caller"] if name == "caller" else app_raw["repo"]
        if value.count("/") != 1:
            raise ProfileError(f"{name} must be owner/name, not {value!r}")

    timeouts = dict(DEFAULT_TIMEOUTS)
    timeouts.update(raw.get("timeouts") or {})

    return Profile(
        caller=raw["caller"],
        domain=str(raw["domain"]).strip().lower(),
        caller_workflow=raw.get("callerWorkflow") or "enclavize.yml",
        rescue_key_id=raw.get("rescueKeyId") or "",
        transfer=transfer,
        timeouts=timeouts,
        app=App(
            repo=app_raw["repo"],
            ref=app_raw.get("ref") or "",
            url=app_raw.get("url") or "",
            results_url=app_raw.get("resultsUrl") or "",
            teardown=app_raw.get("teardown") or "",
        ),
    )


# --- what the caller's own workflow tells us ------------------------------


@dataclass(frozen=True)
class Caller:
    """Everything derivable from the caller's workflow file."""

    signer_workflow: str
    """`<owner>/<repo>/<path>` — exactly what --signer-workflow expects."""

    ref: str
    """What the caller pinned to. A sha means the proof is anchored; a branch
    name means it moves, which is fine while developing and not otherwise."""

    inputs: frozenset
    secrets: frozenset
    permissions: dict

    @property
    def pinned_to_a_commit(self) -> bool:
        return len(self.ref) == 40 and all(c in "0123456789abcdef" for c in self.ref)


def derive_caller(workflow_text: str) -> Caller:
    """Read the caller's workflow rather than being told what it calls.

    The `uses:` line is the single source of truth for the signer identity: it
    is what GitHub actually resolves, so deriving from it cannot disagree with
    what really signed the statement.
    """
    doc = yaml.safe_load(workflow_text) or {}

    triggers = doc.get(ON) or doc.get("on") or {}
    dispatch = (triggers or {}).get("workflow_dispatch") or {}
    inputs = frozenset((dispatch.get("inputs") or {}).keys())

    calling = [job for job in (doc.get("jobs") or {}).values()
               if isinstance(job, dict) and job.get("uses")]
    if not calling:
        raise ProfileError("the caller workflow has no job with a `uses:` — nothing to verify against")
    if len(calling) > 1:
        raise ProfileError("the caller workflow calls more than one reusable workflow; cannot tell which signs")

    job = calling[0]
    uses = str(job["uses"])
    if "@" not in uses:
        raise ProfileError(f"`uses: {uses}` has no @ref, so there is nothing pinned")
    path, _, ref = uses.rpartition("@")

    return Caller(
        signer_workflow=path,
        ref=ref,
        inputs=inputs,
        secrets=frozenset((job.get("secrets") or {}).keys()),
        permissions=dict(job.get("permissions") or {}),
    )


def caller_problems(caller: Caller) -> list:
    """Everything that would stop this caller being driven. Empty means usable.

    Reported all at once and up front, because the alternative is a dispatch
    that fails forty minutes into a run for a reason the log does not explain.
    """
    problems = []

    missing_inputs = REQUIRED_INPUTS - caller.inputs
    if missing_inputs:
        problems.append(
            "workflow_dispatch is missing inputs: " + ", ".join(sorted(missing_inputs))
            + " — this suite dispatches the caller, so it has to accept them"
        )

    for name, level in REQUIRED_PERMISSIONS.items():
        if caller.permissions.get(name) != level:
            problems.append(
                f"the calling job does not grant {name}: {level} — a reusable workflow "
                "receives the intersection of its own permissions and the caller's, so "
                "leaving it out means no signature"
            )

    if "/.github/workflows/" not in caller.signer_workflow:
        problems.append(f"`uses: {caller.signer_workflow}` does not name a workflow file")

    return problems


# --- talking to GitHub ----------------------------------------------------


def gh(*args, check: bool = True, parse_json: bool = False):
    """Run gh and return its stdout. The suite shells out rather than using the
    API directly so that what it exercises is the command a person would run."""
    result = subprocess.run(
        ("gh",) + args, capture_output=True, text=True, check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"gh {' '.join(args)} failed ({result.returncode}):\n{result.stderr.strip()}"
        )
    if parse_json:
        return json.loads(result.stdout or "null")
    return result


def repo_id(repo: str) -> int:
    """The numeric id the statement records. Names can be reassigned; ids cannot."""
    return int(gh("api", f"repos/{repo}", "--jq", ".id", check=True).stdout.strip())

def head_sha(repo: str, ref: str = "") -> str:
    """The commit to apply. Resolved here so a profile need not pin one."""
    target = ref or gh("api", f"repos/{repo}", "--jq", ".default_branch").stdout.strip()
    return gh("api", f"repos/{repo}/commits/{target}", "--jq", ".sha").stdout.strip()


def caller_workflow_text(profile: Profile) -> str:
    """Fetch the caller's workflow file from GitHub, not from disk: the caller
    lives in another repository and what matters is what GitHub will run."""
    encoded = gh(
        "api", f"repos/{profile.caller}/contents/.github/workflows/{profile.caller_workflow}",
        "--jq", ".content",
    ).stdout
    return base64.b64decode(encoded).decode("utf-8")


def verify_attestation(artifact, *, caller: str, signer_workflow: str,
                       predicate_type: str = PREDICATE_TYPE, bundle=None) -> bool:
    """True when gh accepts the attestation. False is a real answer here — the
    negative checks depend on being able to see a verify fail."""
    args = ["attestation", "verify", str(artifact), "--repo", caller,
            "--signer-workflow", signer_workflow, "--predicate-type", predicate_type]
    if bundle:
        args += ["--bundle", str(bundle)]
    return gh(*args, check=False).returncode == 0


# --- waiting --------------------------------------------------------------


def poll(check, *, timeout: int, interval: int = 15, what: str = "condition"):
    """Call `check` until it returns something truthy. Raises on timeout.

    Everything worth asserting end-to-end arrives late: certificates validate,
    distributions deploy, DNS propagates. The message names what was being
    waited for, because a bare timeout in a two-hour run says nothing.
    """
    deadline = time.monotonic() + timeout
    last = None
    while True:
        try:
            last = check()
        except Exception as exc:  # noqa: BLE001 - a not-yet-existing thing raises
            last = f"{type(exc).__name__}: {exc}"
        else:
            if last:
                return last
        if time.monotonic() >= deadline:
            raise TimeoutError(f"waited {timeout}s for {what}; last saw {last!r}")
        time.sleep(interval)


def fetch(url: str, *, timeout: int = 20):
    """GET a URL, returning (status, body-bytes). Never raises on an HTTP error
    status, because a 403 or a 404 is often the thing being asserted."""
    request = urllib.request.Request(url, headers={"cache-control": "no-cache"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def post_json(url: str, payload: dict, *, api_key: str, timeout: int = 40):
    """POST to the apply endpoint. Returns (status, decoded-body-or-bytes)."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "x-api-key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body, status = response.read(), response.status
    except urllib.error.HTTPError as exc:
        body, status = exc.read(), exc.code
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


# --- the environment ------------------------------------------------------


def env_secret(name: str, *, required: bool = False) -> str:
    value = os.environ.get(name, "")
    if required and not value:
        raise ProfileError(f"{name} must be set; secrets are never read from the profile")
    return value
