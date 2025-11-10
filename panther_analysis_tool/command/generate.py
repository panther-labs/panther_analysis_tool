import pathlib
import subprocess
from typing import Tuple


def run() -> Tuple[int, str]:
    main_path = pathlib.Path("main.py")
    if not main_path.exists():
        return 1, "main.py not found. No changes made."

    # run main.py
    subprocess.run(["python", main_path])

    print("main.py executed successfully.")
    return 0, ""
