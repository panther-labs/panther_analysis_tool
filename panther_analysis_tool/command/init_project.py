import os
from typing import Tuple


def run() -> Tuple[int, str]:
    setup_folder_structure()
    return 0, "Project initialized"


def setup_folder_structure() -> None:
    if not os.path.exists(".gitignore"):
        with open(".gitignore", "w", encoding="utf-8") as gitignore_file:

            gitignore_file.write("# Cache values\n")
            gitignore_file.write(".cache/\n")

            gitignore_file.write("\n# Panther settings\n")
            gitignore_file.write(".panther_settings.*\n")

            gitignore_file.write("\n# Python\n")
            gitignore_file.write("__pycache__/\n")
            gitignore_file.write("*.pyc\n")

            gitignore_file.write("\n# Panther\n")
            gitignore_file.write("panther-analysis-*.zip\n")

            gitignore_file.write("\n# IDEs\n")
            gitignore_file.write(".vscode/\n")
            gitignore_file.write(".idea/\n")
