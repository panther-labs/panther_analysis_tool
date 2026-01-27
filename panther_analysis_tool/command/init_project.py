import logging
import pathlib
import subprocess  # nosec:B404
from typing import Tuple

from panther_analysis_tool.constants import PAT_ROOT_FILE_NAME
from panther_analysis_tool.core import analysis_cache, git_helpers


def run(working_dir: str) -> Tuple[int, str]:
    analysis_cache.update_with_latest_panther_analysis(show_progress_bar=True)
    setup_git_ignore()
    enable_rerere()
    pat_root_created = setup_pat_root(pathlib.Path(working_dir))
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
        content += f"# {ignorable['name']}\n"
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
    git_root = pathlib.Path(git_helpers.git_root())
    if git_root == working_dir:
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
    print("  * Run `pat clone <id>` to create a clone of a detection you want to use in your repo.")
    print(
        "  * Run `pat clone --filter LogTypes=<LOG_TYPE>` to create clones of all detections for a given log type you have onboarded."
    )
    print(
        "  * Run `pat test` to test your content and then run `pat upload` to upload your content to Panther."
    )

    print(
        "\nOr run `pat --help` to see all available commands. "
        "Visit https://docs.panther.com/panther-developer-workflows/overview for more information."
    )
