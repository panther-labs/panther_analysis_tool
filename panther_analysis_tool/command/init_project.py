import os
from pathlib import Path
from typing import Tuple


def run(working_dir: str) -> Tuple[int, str]:
    setup_folder_structure(Path(working_dir))
    return 0, ""


def setup_folder_structure(working_dir: Path) -> None:
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


    print("Project is ready to use!\n")

    print("Next, you can start exploring and using Panther out of the box content:")
    print("    Run `pat explore` to see the available content.")
    print("    Run `pat enable` to create a clone of a detection you want to use.")
    print("    Run `pat enable --filter LogType=<LOG_TYPE>` to enable all detections for a given log type you have onboarded.")
    print("    Run `pat test` to test your content and then run `pat upload` to upload your content to Panther.")

    print("\nOr run `pat --help` to see all available commands. Visit https://docs.panther.com/panther-developer-workflows/overview for more information.")