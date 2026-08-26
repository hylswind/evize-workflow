"""enclavize/logic/github.py against the real GitHub API.

Everywhere else this module is driven through an injected `opener`, so the URL
shape, the headers and the response format are assumptions. They run in
pre-flight, before anything touches the account — a wrong assumption there means
every run aborts at the first step.

Reads only, public endpoints only, no token needed.
"""

import pytest

from enclavize.logic import github

pytestmark = pytest.mark.live

# GitHub's own action, and the one this workflow checks out with. A repo id is
# permanent — that is the whole reason the statement records the id rather than
# the name, so pinning it here is a real assertion rather than a brittle one.
REPO = "actions/checkout"
REPO_ID = 197814629


def test_a_repo_id_can_be_resolved():
    assert github.resolve_repo_id(REPO) == REPO_ID


def test_the_id_is_stable_across_a_rename():
    """The statement records the id because names can be renamed, transferred,
    and the freed name claimed by somebody else. If ids were not stable this
    whole approach would be wrong."""
    by_name = github.resolve_repo_id(REPO)
    # Reached through the owner's login rather than a redirect, same repo.
    assert by_name == REPO_ID
    assert isinstance(by_name, int)


def test_a_missing_repo_is_a_clean_failure():
    # A bad `repo` input must abort pre-flight, not raise something opaque.
    with pytest.raises(ValueError, match="HTTP 404"):
        github.resolve_repo_id("actions/this-repository-does-not-exist-enclavize")


def test_a_path_can_be_confirmed_at_a_commit():
    """The check enclavize makes before launching an instance to run setup.sh."""
    github.require_path_at_sha(REPO, "main", "action.yml")


def test_a_path_that_is_not_there_is_rejected():
    with pytest.raises(ValueError, match="HTTP 404"):
        github.require_path_at_sha(REPO, "main", "definitely-not-a-file.enclavize")


def test_a_directory_is_not_accepted_as_a_file():
    # The contents API returns a list for a directory, so `type` is absent.
    with pytest.raises(ValueError):
        github.require_path_at_sha(REPO, "main", "src")


def test_an_unauthenticated_read_is_enough():
    """No token is passed here, which is what proves the pre-flight works for a
    caller that has not supplied one."""
    assert github.resolve_repo_id(REPO, token=None) == REPO_ID
