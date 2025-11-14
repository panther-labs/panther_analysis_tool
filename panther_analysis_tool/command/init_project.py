import os
from pathlib import Path
from typing import Tuple


def run(working_dir: str) -> Tuple[int, str]:
    setup_git_ignore(Path(working_dir))
    print_ready_message()
    return 0, ""


def setup_git_ignore(working_dir: Path) -> None:
    if not os.path.exists(working_dir / ".gitignore"):
        print(".gitignore file created")
        Path(working_dir / ".gitignore").touch()

    with open(working_dir / ".gitignore", "r+", encoding="utf-8") as gitignore_file:
        ignorables = [
            {
                "name": "Cache values",
                "values": [".cache/"],
            },
            {
                "name": "Panther settings",
                "values": [".panther_settings.*"],
            },
            {
                "name": "Python",
                "values": ["__pycache__/", "*.pyc"],
            },
            {
                "name": "Panther",
                "values": ["panther-analysis-*.zip"],
            },
            {
                "name": "IDEs",
                "values": [".vscode/", ".idea/"],
            },
        ]

        content = gitignore_file.read()
        if not content.endswith("\n"):
            gitignore_file.write("\n")
        for ignorable in ignorables:
            for value in ignorable["values"]:
                if value not in content:
                    gitignore_file.write(f"# {ignorable['name']}\n")
                    gitignore_file.write(f"{value}\n\n")


def print_ready_message() -> None:
    print("Project is ready to use!\n")

    print("Next, you can start exploring and using Panther out of the box content:")
    print(
        "    Run `pat pull` to pull and merge the latest content from Panther Analysis with your own. Rerun this every time you want to update your content."
    )
    print("    Run `pat explore` to see the available content.")
    print(
        "    Run `pat enable <id>` to create a clone of a detection you want to use in your repo."
    )
    print(
        "    Run `pat enable --filter LogTypes=<LOG_TYPE>` to enable all detections for a given log type you have onboarded."
    )
    print(
        "    Run `pat test` to test your content and then run `pat upload` to upload your content to Panther."
    )

    print(
        "\nOr run `pat --help` to see all available commands. "
        "Visit https://docs.panther.com/panther-developer-workflows/overview for more information."
    )
