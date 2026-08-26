"""Wait.

Long enough for the sealing actions to reach event history and for the console
lockout to replicate globally. There is no signal to poll for either, so this is
a fixed hold rather than a wait-until.

Zero is a legitimate value: a run that is not going to read the history has
nothing to wait for it to finish arriving.
"""

import time


def wait(seconds: int, *, sleep=time.sleep) -> None:
    sleep(seconds)
