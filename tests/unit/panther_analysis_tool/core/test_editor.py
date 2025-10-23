import tempfile

from panther_analysis_tool.core import editor

base_file = """
global_thing = "base"

def rule(event):
    return True
"""

users_file = """
global_thing = "user change"

def rule(event):
    return True

def user_func():
    return True
"""

panthers_file = """
# panther comment
global_thing = "panther change"

def rule(event):
    return True
"""


def _edit_file() -> None:
    with (
        tempfile.NamedTemporaryFile(delete=False) as users_file_temp,
        tempfile.NamedTemporaryFile(delete=False) as base_file_temp,
        tempfile.NamedTemporaryFile(delete=False) as panthers_file_temp,
        tempfile.NamedTemporaryFile(delete=False) as output_file_temp,
    ):
        users_file_temp.write(users_file.encode())
        users_file_temp.flush()
        base_file_temp.write(base_file.encode())
        base_file_temp.flush()
        panthers_file_temp.write(panthers_file.encode())
        panthers_file_temp.flush()

        print(f"users_file_temp: {users_file_temp.name}")
        print(f"base_file_temp: {base_file_temp.name}")
        print(f"panthers_file_temp: {panthers_file_temp.name}")
        print(f"output_file_temp: {output_file_temp.name}")

        # mocker.patch("os.getenv", return_value="vi")
        editor.merge_files_in_editor(
            editor.MergeableFiles(
                users_file=users_file_temp.name,
                base_file=base_file_temp.name,
                panthers_file=panthers_file_temp.name,
                output_file=output_file_temp.name,
            )
        )

        print()
        print(output_file_temp.read())


if __name__ == "__main__":
    _edit_file()
