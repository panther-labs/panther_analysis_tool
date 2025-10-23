import dataclasses
import os
import pathlib
import subprocess  # nosec:B404
import time
from datetime import datetime

from panther_analysis_tool.constants import DEFAULT_EDITOR

_jetbrains_editors = ["goland"]

# def edit_file(contents: bytes) -> bytes:
#     # create a temp file and write the spec to it
#     with tempfile.NamedTemporaryFile(delete=False) as temp_file:
#         temp_file.write(contents)
#         temp_file.flush()

#         # launch the editor with the temp file and wait for it to finish
#         editor = os.getenv("EDITOR", DEFAULT_EDITOR)
#         subprocess.run([editor, temp_file.name], check=True)  # nosec:B603

#         # read the temp file and compare it to the original spec
#         with open(temp_file.name, "rb") as f:
#             return f.read()


# def edit_file(users: bytes, base: bytes, panthers: bytes) -> bytes:
#     editor = os.getenv("EDITOR", DEFAULT_EDITOR).lower()

#     with (
#         tempfile.NamedTemporaryFile(delete=False) as result_file,
#         tempfile.NamedTemporaryFile(delete=False) as users_file,
#         tempfile.NamedTemporaryFile(delete=False) as base_file,
#         tempfile.NamedTemporaryFile(delete=False) as panthers_file,
#     ):
#         users_file.write(users)
#         users_file.flush()
#         base_file.write(base)
#         base_file.flush()
#         panthers_file.write(panthers)
#         panthers_file.flush()

#         args = [editor]
#         match editor:
#             case "goland" | "pycharm":
#                 args.extend(["merge", users_file.name, base_file.name, panthers_file.name])
#             case "code" | "cursor":
#                 args.extend(["--merge", users_file.name, base_file.name, panthers_file.name])
#             case _:
#                 args.extend([users_file.name, base_file.name, panthers_file.name])

#         subprocess.run(args, check=True)  # nosec:B603

#         return result_file.read()


@dataclasses.dataclass
class MergeableFiles:
    users_file: str = ""  # local
    base_file: str = ""  # base
    panthers_file: str = ""  # remote
    output_file: str = ""  # output

    # used for editors that don't have a built in 3-way merge tool
    premerged_file: str = ""

    def validate(self, premerged: bool) -> None:
        if premerged:
            if self.premerged_file == "":
                raise ValueError("Premerged file is required")
            if not pathlib.Path(self.premerged_file).exists():
                raise FileNotFoundError(f"Premerged file {self.premerged_file} not found")
        else:
            if self.users_file == "":
                raise ValueError("User's file is required")
            if not pathlib.Path(self.users_file).exists():
                raise FileNotFoundError(f"User's file {self.users_file} not found")
            if self.base_file == "":
                raise ValueError("Base file is required")
            if not pathlib.Path(self.base_file).exists():
                raise FileNotFoundError(f"Base file {self.base_file} not found")
            if self.panthers_file == "":
                raise ValueError("Panther's file is required")
            if not pathlib.Path(self.panthers_file).exists():
                raise FileNotFoundError(f"Panther's file {self.panthers_file} not found")
            if self.output_file == "":
                raise ValueError("Output file is required")
            if not pathlib.Path(self.output_file).exists():
                raise FileNotFoundError(f"Output file {self.output_file} not found")


def merge_files_in_editor(files: MergeableFiles) -> None:
    editor = os.getenv("EDITOR", DEFAULT_EDITOR).lower()

    needs_wait = False
    args = [editor]
    match editor:
        # jetbrains editors, not all their products are included in this list
        case (
            "idea"
            | "pycharm"
            | "webstorm"
            | "phpstorm"
            | "rubymine"
            | "clion"
            | "goland"
            | "rider"
            | "appcode"
            | "rustrover"
            | "dataspell"
        ):
            files.validate(premerged=False)
            needs_wait = True
            args.extend(
                [
                    "--wait",
                    "merge",
                    files.users_file,
                    files.panthers_file,
                    files.base_file,
                    files.output_file,
                ]
            )
        case "code" | "cursor":
            files.validate(premerged=False)
            args.extend(
                [
                    "--merge",
                    files.users_file,
                    files.panthers_file,
                    files.base_file,
                    files.output_file,
                ]
            )
        case "emacs":
            files.validate(premerged=False)
            args.extend(
                [
                    "--eval",
                    f'"(ediff-merge-files-with-ancestor "{files.users_file}" "{files.panthers_file}" "{files.base_file}" "nil" "{files.output_file}")"',
                ]
            )
        case "vim":
            files.validate(premerged=False)
            args.extend(
                ["-d", files.users_file, files.base_file, files.panthers_file, files.output_file]
            )
        case _:
            files.validate(premerged=True)
            args.append(files.premerged_file)

    subprocess.run(args, check=True)  # nosec:B603
    if needs_wait:
        wait_for_file_modification(files.output_file)


def wait_for_file_modification(filepath: str) -> None:
    timeout = 1 * 60 * 60  # 1 hour in seconds
    wait_interval = 0.5  # in seconds

    # Get initial modification time
    file = pathlib.Path(filepath)
    initial_mtime = file.stat().st_mtime
    start_time = datetime.now()

    while True:
        time.sleep(wait_interval)
        current_mtime = file.stat().st_mtime

        if current_mtime > initial_mtime:
            return

        if datetime.now().timestamp() - start_time.timestamp() > timeout:
            raise TimeoutError(f"File {filepath} not modified within {timeout} seconds")
