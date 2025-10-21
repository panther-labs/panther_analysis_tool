import os
import shutil
import subprocess  # nosec:B404

import requests

from panther_analysis_tool.constants import CACHE_DIR

CLONED_REPO_PATH = CACHE_DIR / "panther-analysis"
CLONED_VERSIONS_FILE_PATH = CLONED_REPO_PATH / ".versions.yml"


def panther_analysis_release_url(tag: str = "latest") -> str:
    """
    Get the panther analysis release URL.
    """
    return f"https://api.github.com/repos/panther-labs/panther-analysis/releases/{tag}"


def panther_analysis_latest_release_commit() -> str:
    """
    Get the commit hash for the latest release of Panther Analysis.
    """
    response = requests.get(panther_analysis_release_url(), timeout=10)
    return response.json()["tag_name"]


def clone_panther_analysis(branch: str, commit: str = "") -> None:
    """
    Clone the Panther Analysis repository to the cache directory.
    """
    if CLONED_REPO_PATH.exists():
        shutil.rmtree(CLONED_REPO_PATH)

    try:
        completed_process = subprocess.run(  # nosec:B607 B603
            [
                "git",
                "clone",
                "-b",
                branch,
                "https://github.com/panther-labs/panther-analysis.git",
                str(CLONED_REPO_PATH),
            ],
            check=True,
            capture_output=True,
        )
        if completed_process.returncode != 0:
            raise RuntimeError(
                f"Failed to clone panther-analysis: return code was {completed_process.returncode}"
            )

        # these have yaml files so removing them to avoid having to read them
        shutil.rmtree(CLONED_REPO_PATH / "test_scenarios")
        shutil.rmtree(CLONED_REPO_PATH / "templates")
        shutil.rmtree(CLONED_REPO_PATH / ".github")

        cwd = os.getcwd()
        os.chdir(CLONED_REPO_PATH)

        if commit != "":
            completed_process = subprocess.run(  # nosec:B607 B603
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


def delete_cloned_panther_analysis() -> None:
    """
    Delete the cloned Panther Analysis repository from the cache directory.
    """
    shutil.rmtree(CLONED_REPO_PATH)


def get_panther_analysis_file_contents(commit: str, file_path: str) -> str:
    file_path = (
        file_path.strip().lstrip("./").lstrip("/")
    )  # remove leading ./ if present or any leading /
    url = f"https://raw.githubusercontent.com/panther-labs/panther-analysis/{commit}/{file_path}"
    response = requests.get(url, timeout=10)
    return response.text
