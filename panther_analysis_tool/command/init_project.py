import contextlib
import io
import json
import logging
import pathlib
import subprocess  # nosec:B404
from typing import Tuple

from panther_analysis_tool.constants import PAT_ROOT_FILE_NAME
from panther_analysis_tool.core import analysis_cache, git_helpers


def run(working_dir: str) -> Tuple[int, str]:
    """Initialize a new Panther project.

    Args:
        working_dir: Directory to initialize in.

    Returns:
        Tuple of (return_code, message_string).
    """
    from panther_analysis_tool.main import is_json_mode

    json_mode = is_json_mode()

    # In JSON mode, suppress stdout from helpers so only our JSON goes to stdout.
    # Progress bars and informational prints go to a discarded buffer.
    ctx = contextlib.redirect_stdout(io.StringIO()) if json_mode else contextlib.nullcontext()

    with ctx:
        analysis_cache.update_with_latest_panther_analysis(show_progress_bar=not json_mode)
        setup_git_ignore()
        enable_rerere()
        pat_root_created = setup_pat_root(pathlib.Path(working_dir))

    if json_mode:
        print(
            json.dumps(
                {
                    "command": "init",
                    "return_code": 0,
                    "status": "success",
                    "data": {"pat_root_created": pat_root_created},
                }
            )
        )
        return 0, ""
    print_ready_message(pat_root_created)
    return 0, ""


def setup_git_ignore() -> None:
    gitignore_file = git_helpers.git_root() / ".gitignore"
    if not gitignore_file.exists():
        print(".gitignore file created")
        gitignore_file.touch()

    ignorables = [
        {
            "name": "Panther settings",
            "values": [".panther_settings.*"],
        },
        {
            "name": "Python",
            "values": ["__pycache__/", "*.pyc", ".mypy_cache/", ".pytest_cache/"],
        },
        {
            "name": "Panther",
            "values": ["panther-analysis-*.zip", ".cache/"],
        },
        {
            "name": "IDEs",
            "values": [".vscode/", ".idea/"],
        },
    ]

    content = gitignore_file.read_text()

    # ensure ends with two newlines
    if content != "" and not content.endswith("\n\n"):
        if not content.endswith("\n"):
            content += "\n"
        content += "\n"

    for ignorable in ignorables:
        section_comment = f"# {ignorable['name']}\n"
        section_exists = section_comment in content
        missing_values = [v for v in ignorable["values"] if v not in content]

        if section_exists:
            if missing_values:
                insertion = "".join(f"{v}\n" for v in missing_values)
                content = content.replace(section_comment, section_comment + insertion, 1)
        else:
            content += section_comment
            for value in ignorable["values"]:
                if value not in content:
                    content += f"{value}\n"
            content += "\n"

    gitignore_file.write_text(content)


def enable_rerere() -> None:
    proc = subprocess.run(  # nosec:B603 B607
        ["git", "config", "rerere.enabled", "true"], check=True, capture_output=True
    )
    if proc.stderr is not None and proc.stderr.decode("utf-8") != "":
        logging.error("Failed to enable git rerere: %s", proc.stderr.decode("utf-8"))


def setup_pat_root(working_dir: pathlib.Path) -> bool:
    """
    `.pat-root` file is used to track the root of the Panther project if the root is not the same as the git root.
    Create a `.pat-root` file in the working directory if it doesn't already exist.
    If the working directory is the same as the git root, do not create the `.pat-root` file.

    Args:
        working_dir (pathlib.Path): The current working directory.

    Returns:
        bool: True if the `.pat-root` file was created, False otherwise.
    """
    git_root = pathlib.Path(git_helpers.git_root()).absolute()
    if git_root == working_dir.absolute():
        return False

    pat_root_file = working_dir / PAT_ROOT_FILE_NAME
    if pat_root_file.exists():
        return False

    pat_root_file.touch()
    pat_root_file.write_text(
        "# File created by Panther Analysis Tool to track the root of your Panther project. Please commit this file and do not delete it.\n"
    )
    return True


def print_ready_message(pat_root_created: bool) -> None:
    print("Project is ready to use!\n")

    if pat_root_created:
        print(
            "`init` command was not run in the same directory as the git root. "
            "`.pat-root` file created in current directory and will be used as the root "
            "of your Panther project for future `pat` commands.\n"
        )

    print("Next, you can start exploring and using Panther out of the box content:")
    print("  * Run `pat explore` to see the available content.")
    print("  * Run `pat install <id>` to install a detection you want to use in your repo.")
    print(
        "  * Run `pat install --filter LogTypes=<LOG_TYPE>` to install all detections for a given log type you have onboarded."
    )
    print(
        "  * Run `pat test` to test your content and then run `pat upload` to upload your content to Panther."
    )

    print(
        "\nOr run `pat --help` to see all available commands. "
        "Visit https://docs.panther.com/panther-developer-workflows/overview for more information."
    )
