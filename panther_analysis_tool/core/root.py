import os

from panther_analysis_tool.core import git_helpers


def chdir_to_project_root() -> None:
    """
    Change the current working directory to the project root. This is the git root if `pat init`
    was run in the same directory as the git root, otherwise it is the directory where the `.pat-root` file is located.
    Assumes that project is a git repo and `.pat-root` is inside git repo if it has the file.
    """
    git_root = git_helpers.git_root()
    for root, _, files in os.walk(git_root):
        if ".pat-root" in files:
            os.chdir(root)
            return

    os.chdir(git_root)
