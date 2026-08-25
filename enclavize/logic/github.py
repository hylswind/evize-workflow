"""What a run needs from GitHub, and how to read its own identity.

owner/name can be renamed, transferred, and the freed name claimed by someone
else; the numeric repo id cannot, so the statement records the id and the run
looks it up. That lookup happens before anything irreversible, making a bad
repo a pre-seal failure.

A reusable workflow also has to discover *itself*: inside one, github.repository
is the caller, not enclavize. The pinned identity comes from job_workflow_ref
and job_workflow_sha, and the launched instance clones from that — so parsing it
correctly is what makes the running setup program the attested one.
"""

import json
import re
import urllib.error
import urllib.request

REPO_API = "https://api.github.com/repos/{repo}"
CONTENTS_API = REPO_API + "/contents/{path}?ref={ref}"

REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _get(url: str, token, opener=None) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    fetch = opener or urllib.request.urlopen
    try:
        with fetch(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise ValueError(f"enclavize: cannot resolve {url}: HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise ValueError(f"enclavize: cannot reach GitHub for {url}: {exc.reason}") from None


def resolve_repo_id(repo: str, *, token=None, opener=None) -> int:
    body = _get(REPO_API.format(repo=repo), token, opener)
    repo_id = body.get("id")
    if not isinstance(repo_id, int):
        raise ValueError(f"enclavize: GitHub returned no id for {repo!r}")
    return repo_id


def require_path_at_sha(repo: str, ref: str, path: str, *, token=None, opener=None) -> None:
    """Fail unless `path` is a file in `repo` at `ref`.

    Used at deploy time to check an app repo ships the setup.sh entrypoint
    before an instance is launched to run it.
    """
    body = _get(CONTENTS_API.format(repo=repo, path=path, ref=ref), token, opener)
    # A directory comes back as a JSON array of its entries, not an object, so
    # the type has to be checked before the lookup rather than after it.
    if not isinstance(body, dict) or body.get("type") != "file":
        raise ValueError(f"enclavize: {path!r} in {repo}@{ref} is not a file")


def parse_job_workflow_ref(ref: str) -> tuple:
    """Split github.job_workflow_ref into (owner/repo, workflow path).

    The value looks like
        owner/repo/.github/workflows/enclavize.yml@refs/heads/main
    and identifies the reusable workflow that is running — which, inside a
    reusable workflow, is the only way to learn enclavize's own repo.
    """
    if not ref:
        raise ValueError("enclavize: job_workflow_ref is empty; not running as a reusable workflow?")
    without_git_ref = ref.split("@", 1)[0]
    parts = without_git_ref.split("/")
    if len(parts) < 3:
        raise ValueError(f"enclavize: cannot parse job_workflow_ref {ref!r}")
    slug = "/".join(parts[:2])
    path = "/".join(parts[2:])
    if not REPO_RE.match(slug):
        raise ValueError(f"enclavize: job_workflow_ref {ref!r} does not start with owner/repo")
    return slug, path


def require_repo(value: str) -> str:
    if not REPO_RE.match(value or ""):
        raise ValueError(f"enclavize: {value!r} is not a valid owner/name repo")
    return value


def require_sha(value: str) -> str:
    if not SHA_RE.match(value or ""):
        raise ValueError(f"enclavize: {value!r} is not a 40-hex commit sha")
    return value
