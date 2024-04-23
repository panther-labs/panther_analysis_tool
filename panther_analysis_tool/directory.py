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

    def clean_me_up(*_: Any) -> None:
        try:
            shutil.rmtree(temp_dir)
        finally:
            pass

    atexit.register(clean_me_up)
    signal.signal(signal.SIGINT, clean_me_up)
    signal.signal(signal.SIGTERM, clean_me_up)
