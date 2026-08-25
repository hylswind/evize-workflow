"""Reading GitHub before the account is touched, and reading enclavize's own
pinned identity — which is the only thing tying the running setup program to the
code the attestation covers."""

import io
import json
import urllib.error

import pytest
from constants import APP_REPO, REPO_ID, SELF_SHA

from enclavize.logic import github


class Response:
    def __init__(self, payload):
        self._body = io.BytesIO(json.dumps(payload).encode())

    def read(self):
        return self._body.read()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def responder(payload):
    return lambda _req, timeout=None: Response(payload)


def raiser(exc):
    def _raise(_req, timeout=None):
        raise exc

    return _raise


def test_repo_id_is_read_from_the_api():
    assert github.resolve_repo_id(APP_REPO, opener=responder({"id": REPO_ID})) == REPO_ID


def test_a_repo_without_a_numeric_id_is_rejected():
    with pytest.raises(ValueError, match="no id"):
        github.resolve_repo_id(APP_REPO, opener=responder({"id": "not-a-number"}))


def test_a_missing_repo_fails_before_anything_is_touched():
    error = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
    with pytest.raises(ValueError, match="HTTP 404"):
        github.resolve_repo_id(APP_REPO, opener=raiser(error))


def test_an_unreachable_github_is_reported_clearly():
    with pytest.raises(ValueError, match="cannot reach GitHub"):
        github.resolve_repo_id(APP_REPO, opener=raiser(urllib.error.URLError("offline")))


def test_require_path_accepts_a_file():
    github.require_path_at_sha(APP_REPO, SELF_SHA, "setup.sh", opener=responder({"type": "file"}))


def test_require_path_rejects_a_directory():
    # The contents API answers with an array of entries for a directory, not an
    # object with a type. An earlier fake here returned a dict, and the code
    # that trusted it raised AttributeError against the real API.
    listing = [{"name": "a.txt", "type": "file"}, {"name": "b.txt", "type": "file"}]
    with pytest.raises(ValueError, match="is not a file"):
        github.require_path_at_sha(APP_REPO, SELF_SHA, "src", opener=responder(listing))


def test_require_path_rejects_anything_that_is_not_a_file():
    for body in ({"type": "dir"}, {"type": "symlink"}, {}, []):
        with pytest.raises(ValueError, match="is not a file"):
            github.require_path_at_sha(APP_REPO, SELF_SHA, "x", opener=responder(body))


@pytest.mark.parametrize(
    "ref,slug,path",
    [
        # A branch ref and a sha ref: the two forms GitHub actually produces.
        (
            "acme/enclavize-workflow/.github/workflows/enclavize.yml@refs/heads/main",
            "acme/enclavize-workflow",
            ".github/workflows/enclavize.yml",
        ),
        (
            "octo-org/repo.name/.github/workflows/x.yml@" + "a" * 40,
            "octo-org/repo.name",
            ".github/workflows/x.yml",
        ),
    ],
)
def test_job_workflow_ref_is_split_into_repo_and_path(ref, slug, path):
    assert github.parse_job_workflow_ref(ref) == (slug, path)


def test_an_empty_job_workflow_ref_is_rejected():
    # Empty means the workflow is not running as a reusable one, so the sha it
    # would clone is not the attested code.
    with pytest.raises(ValueError, match="job_workflow_ref is empty"):
        github.parse_job_workflow_ref("")


def test_a_malformed_job_workflow_ref_is_rejected():
    with pytest.raises(ValueError, match="cannot parse"):
        github.parse_job_workflow_ref("nonsense@refs/heads/main")


@pytest.mark.parametrize("value", ["acme/app", "octo-org/repo.name_v2"])
def test_valid_repos_are_accepted(value):
    assert github.require_repo(value) == value


# One per rejection reason: wrong shape, a shell metacharacter, a non-string.
@pytest.mark.parametrize("value", ["a/b/c", "a/b;rm -rf /", None])
def test_invalid_repos_are_rejected(value):
    # The repo lands in a shell command inside user-data.
    with pytest.raises(ValueError):
        github.require_repo(value)


@pytest.mark.parametrize("value", ["0123456789abcdef" * 2 + "01234567"])
def test_valid_shas_are_accepted(value):
    assert github.require_sha(value) == value


# Uppercase is the subtle one: 40 hex characters, but git writes lowercase.
@pytest.mark.parametrize("value", ["A" * 40, "a" * 41, None])
def test_invalid_shas_are_rejected(value):
    with pytest.raises(ValueError):
        github.require_sha(value)
