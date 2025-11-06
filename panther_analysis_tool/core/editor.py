import dataclasses
import os
import pathlib
import subprocess  # nosec:B404

from panther_analysis_tool.constants import DEFAULT_EDITOR


@dataclasses.dataclass
class MergeableFiles:
    users_file: pathlib.Path  # local
    base_file: pathlib.Path  # base
    panthers_file: pathlib.Path  # remote
    output_file: pathlib.Path  # output

    # used for editors that don't have a built in 3-way merge tool
    premerged_file: pathlib.Path

    def validate(self, premerged_required: bool) -> None:
        if premerged_required:
            if not self.premerged_file.exists():
                raise FileNotFoundError(f"Premerged file {self.premerged_file} not found")
        else:
            if not self.users_file.exists():
                raise FileNotFoundError(f"User's file {self.users_file} not found")
            if not self.base_file.exists():
                raise FileNotFoundError(f"Base file {self.base_file} not found")
            if not self.panthers_file.exists():
                raise FileNotFoundError(f"Panther's file {self.panthers_file} not found")
            if not self.output_file.exists():
                raise FileNotFoundError(f"Output file {self.output_file} not found")


def merge_files_in_editor(files: MergeableFiles) -> bool:
    """
    Merge files in an editor. Editor is read from the EDITOR environment variable.

    Args:
        files: The MergeableFiles object.

    Returns:
        True if the editor returns before the merge is solved because it is solved asynchronously, False otherwise.
    """
    editor = os.getenv("EDITOR", DEFAULT_EDITOR).lower()

    args = [editor]
    async_edit = True
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
            files.validate(premerged_required=False)
            args.extend(
                [
                    "merge",
                    str(files.users_file),
                    str(files.panthers_file),
                    str(files.base_file),
                    str(files.output_file),
                ]
            )
        case "vi" | "vim":
            async_edit = False
            files.validate(premerged_required=True)
            args.append(str(files.premerged_file))
        case _:
            files.validate(premerged_required=True)
            args.append(str(files.premerged_file))

    subprocess.run(args, check=True)  # nosec:B603
    return async_edit
