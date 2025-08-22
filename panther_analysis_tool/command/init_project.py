from typing import Tuple
import os

def run() -> Tuple[int, str]:
    setup_folder_structure()
    return 0, "Project initialized"

def setup_folder_structure() -> None:
    if not os.path.exists(".gitignore"):
        with open(".gitignore", "w", encoding="utf-8") as gitignore_file:
            gitignore_file.write(".cache/\n")
            gitignore_file.write(".panther_settings.*\n")
            gitignore_file.write("*.pyc\n")
            gitignore_file.write("panther-analysis-*.zip\n")
