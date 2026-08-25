"""Literals shared by the offline tests.

A module of its own rather than conftest, because tests/aws has a conftest too
and the two would shadow each other on sys.path.

These are deliberately not the production constants: threading values through
proves the code uses what it was given rather than re-reading a module global.
"""

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"
DOMAIN = "example.com"
APP_REPO = "acme/app"
SELF_REPO = "acme/enclavize-workflow"
SELF_SHA = "a" * 40
REPO_ID = 1318129369
GO_PARAM = "/test/go-flag"
TEST_PREFIX = "t-test-"

STATEMENT_KEYS = [
    "accountID",
    "domain",
    "start",
    "holdSeconds",
    "repoID",
    "debug",
    "bypasses",
]


def clock(values):
    """A monotonic-clock stand-in that walks a scripted list.

    Returns each value in turn and then repeats the last, so a poll loop can be
    driven past its deadline without any wall-clock time passing. The last value
    must exceed the deadline or the loop will never end.
    """
    seq = list(values)
    return lambda: seq.pop(0) if len(seq) > 1 else seq[0]


def no_sleep(*_args, **_kwargs):
    return None
