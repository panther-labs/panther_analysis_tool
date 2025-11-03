import os
import pathlib
import tempfile

from panther_analysis_tool.core import editor, git_helpers

conflict_files_path = pathlib.Path(__file__).parent.parent / "fixtures" / "python_merge_conflict"
base_python_path = conflict_files_path / "base_python.py"
customer_python_path = conflict_files_path / "customer_python.py"
panther_python_path = conflict_files_path / "panther_python.py"

raw_customer_python = customer_python_path.read_text()
raw_panther_python = panther_python_path.read_text()
raw_base_python = base_python_path.read_text()


def _edit_file(users_file: str, base_file: str, panthers_file: str) -> None:
    with (
        tempfile.NamedTemporaryFile(delete=False, suffix="_customer_python.py") as users_file_temp,
        tempfile.NamedTemporaryFile(delete=False, suffix="_base_python.py") as base_file_temp,
        tempfile.NamedTemporaryFile(delete=False, suffix="_panther_python.py") as panthers_file_temp,
        tempfile.NamedTemporaryFile(delete=False, suffix="_premerged_python.py") as premerged_file_temp,
        tempfile.NamedTemporaryFile(delete=False, suffix="_output_python.py") as output_file_temp,
    ):
        user_file_path = pathlib.Path(users_file_temp.name)
        base_file_path = pathlib.Path(base_file_temp.name)
        panthers_file_path = pathlib.Path(panthers_file_temp.name)
        output_file_path = pathlib.Path(output_file_temp.name)
        premerged_file_path = pathlib.Path(premerged_file_temp.name)

        user_file_path.write_text(users_file)
        base_file_path.write_text(base_file)
        panthers_file_path.write_text(panthers_file)
        output_file_path.write_text("")

        has_conflict, premerged_file = git_helpers.merge_file(
            user_file_path, base_file_path, panthers_file_path
        )
        premerged_file_path.write_text(premerged_file.decode())

        print(f"Output file: {output_file_temp.name}")
        print(f"Premerged file: {premerged_file_temp.name}")
        print(f"User file: {users_file_temp.name}")
        print(f"Base file: {base_file_temp.name}")
        print(f"Panthers file: {panthers_file_temp.name}")

        editor.merge_files_in_editor(
            editor.MergeableFiles(
                users_file=user_file_path,
                base_file=base_file_path,
                panthers_file=panthers_file_path,
                output_file=output_file_path,
                premerged_file=premerged_file_path,
            )
        )

if __name__ == "__main__":
    print("EDITOR is:", os.getenv("EDITOR"))
    _edit_file(raw_customer_python, raw_base_python, raw_panther_python)
