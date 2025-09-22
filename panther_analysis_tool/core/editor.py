import os
import subprocess  # nosec:B404
import tempfile

from panther_analysis_tool.constants import DEFAULT_EDITOR


def edit_file(contents: bytes) -> bytes:
    # create a temp file and write the spec to it
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(contents)
        temp_file.flush()

        # launch the editor with the temp file and wait for it to finish
        editor = os.getenv("EDITOR", DEFAULT_EDITOR)
        subprocess.run([editor, temp_file.name], check=True)  # nosec:B603

        # read the temp file and compare it to the original spec
        with open(temp_file.name, "rb") as f:
            return f.read()
