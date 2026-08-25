"""One environment tweak moto needs before it loads.

MOTO_IAM_LOAD_MANAGED_POLICIES has to be set before moto initialises its IAM
backend, which is why it lives here rather than in a fixture: without it the
AWS-managed policies enclavize attaches do not exist and attach_* calls fail.

Shared literals live in constants.py, not here — tests/aws has its own conftest
and two modules of the same name shadow each other on sys.path.
"""

import os

os.environ.setdefault("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
