import os
import pathlib
import shutil
import subprocess

import requests

from panther_analysis_tool.constants import CACHE_DIR

_NOT_NEEDED_PANTHER_ANALYSIS_ITEMS = [
    "templates",
    "test_scenarios",
    "style_guides",
    "indexes",
    "packs",
    ".cursor",
    ".scripts",
    ".vscode",
    ".idea",
    ".img",
    ".gitignore",
    ".gitattributes",
    ".github",
    ".bandit",
    ".pre-commit-config.yaml",
    ".pylintrc",
    ".python-version",
    "CLAUDE.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "README.md",
    "deprecated.txt",
    "Dockerfile",
    "LICENSE.txt",
    "Makefile",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
]


def panther_analysis_release_url(tag: str = "latest") -> str:
    """
    Get the panther analysis release URL.
    """
    return f"https://api.github.com/repos/panther-labs/panther-analysis/releases/{tag}"


def panther_analysis_latest_release_commit() -> str:
    """
    Get the commit hash for the latest release of Panther Analysis.
    """
    response = requests.get(panther_analysis_release_url())
    return response.json()["tag_name"]


def clone_panther_analysis(branch: str, commit: str = "") -> None:
    """
    Clone the Panther Analysis repository to the cache directory.
    """
    repo_path = pathlib.Path(CACHE_DIR) / "panther-analysis"
    if repo_path.exists():
        shutil.rmtree(repo_path)

    try:
        completed_process = subprocess.run(  # nosec:B607 B603
            [
                "git",
                "clone",
                "-b",
                branch,
                "https://github.com/panther-labs/panther-analysis.git",
                str(repo_path),
            ],
            check=True,
            capture_output=True,
        )
        if completed_process.returncode != 0:
            raise RuntimeError(
                f"Failed to clone panther-analysis: return code was {completed_process.returncode}"
            )

        # clear out stuff we don't need
        for item in _NOT_NEEDED_PANTHER_ANALYSIS_ITEMS:
            path = repo_path / item
            if path.exists():
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()

        cwd = os.getcwd()
        os.chdir(repo_path)

        if commit != "":
            completed_process = subprocess.run(
                ["git", "checkout", commit],
                check=True,
                capture_output=True,
            )
            if completed_process.returncode != 0:
                raise RuntimeError(
                    f"Failed to checkout commit {commit}: return code was {completed_process.returncode}"
                )

        os.chdir(cwd)  # revert to original cwd
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to clone panther-analysis: {e}")


def get_panther_analysis_file_contents(commit: str, file_path: str) -> str:
    file_path = (
        file_path.strip().lstrip("./").lstrip("/")
    )  # remove leading ./ if present or any leading /
    url = f"https://raw.githubusercontent.com/panther-labs/panther-analysis/{commit}/{file_path}"
    response = requests.get(url)
    return response.text
