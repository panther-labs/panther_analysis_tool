import atexit
import os
import shutil
import signal
import tempfile
from typing import Any
from uuid import uuid4


def setup_temp() -> None:
    """
    Creates a dedicated temporary directory for this process and cleans it up at exit
    """
    temp_dir = os.path.join(tempfile.gettempdir(), f"tmp-PAT-{uuid4()}")
    os.mkdir(temp_dir)
    tempfile.tempdir = temp_dir

    def clean_me_up(signum: int = 0, _frame: Any = None) -> None:
        shutil.rmtree(temp_dir, ignore_errors=True)

        # If this was called as a signal handler, re-raise the signal
        if signum in (signal.SIGINT, signal.SIGTERM):
            # reset to the default python handler and redeliver the signal so that the
            # python process exits properly
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)

    atexit.register(clean_me_up)
    signal.signal(signal.SIGINT, clean_me_up)
    signal.signal(signal.SIGTERM, clean_me_up)
