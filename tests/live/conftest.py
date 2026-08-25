"""Tests that call a real external API but need no credentials.

Only GitHub, and only reads of public endpoints — no account, no keys, nothing
created. They are still kept out of a default `pytest` run because they need
the network and can fail for reasons that have nothing to do with the code.

    ENCLAVIZE_LIVE_TEST=1 pytest -m live tests/live/
"""

import os

collect_ignore_glob = [] if os.environ.get("ENCLAVIZE_LIVE_TEST") == "1" else ["test_*.py"]
