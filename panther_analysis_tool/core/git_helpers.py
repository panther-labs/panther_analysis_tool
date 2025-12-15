import logging
import os
import pathlib
import shutil
import subprocess  # nosec:B404
from typing import Tuple

import requests

from panther_analysis_tool.constants import CACHE_DIR, AutoAcceptOption

CLONED_REPO_PATH = CACHE_DIR / "panther-analysis"
CLONED_VERSIONS_FILE_PATH = CLONED_REPO_PATH / ".versions.yml"
PANTHER_ANALYSIS_SSH_URL = "git@github.com:panther-labs/panther-analysis.git"
PANTHER_ANALYSIS_HTTPS_URL = "https://github.com/panther-labs/panther-analysis.git"
REMOTE_UPSTREAM_NAME = "upstream"
PANTHER_ANALYSIS_MAIN_BRANCH = "main"

_git_root: str | None = None


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


def merge_file(
    user_file_path: pathlib.Path,
    base_file_path: pathlib.Path,
    latest_file_path: pathlib.Path,
    auto_accept: AutoAcceptOption | None = None,
) -> Tuple[bool, bytes]:
    """
    Merge a file with git.

    Args:
        user_file_path (str): The path to the user file.
        base_file_path (str): The path to the base file.
        latest_file_path (str): The path to the latest file.
        auto_accept (AutoAcceptOption | None): The auto accept option.
            If None (default), the user will be prompted to resolve the merge conflict.
            If AutoAcceptOption.YOURS, the user's changes will be used.
            If AutoAcceptOption.PANTHERS, the latest changes will be used.
    Returns:
        bool: True if there was a merge conflict, False otherwise.
        bytes: The merged file contents.
    """
    if not user_file_path.exists():
        raise FileNotFoundError(f"User file {user_file_path} not found")
    if not base_file_path.exists():
        raise FileNotFoundError(f"Base file {base_file_path} not found")
    if not latest_file_path.exists():
        raise FileNotFoundError(f"Latest file {latest_file_path} not found")

    args = [
        "git",
        "merge-file",
        "-p",
    ]

    match auto_accept:
        case AutoAcceptOption.YOURS:
            args.append("--ours")
        case AutoAcceptOption.PANTHERS:
            args.append("--theirs")

    args.extend(
        [
            "-L",
            "yours",
            "-L",
            "base",
            "-L",
            "panthers",
            str(user_file_path),
            str(base_file_path),
            str(latest_file_path),
        ]
    )

    proc = subprocess.run(  # nosec:B607 B603
        args,
        check=False,
        capture_output=True,
    )

    if proc.stderr is not None and proc.stderr.decode("utf-8") != "":
        raise RuntimeError(f"Failed to merge file: {proc.stderr.decode('utf-8')}")

    return proc.returncode != 0, proc.stdout


def get_git_protocol() -> str:
    """
    Get the git protocol of the repository. Either "ssh" or "https".
    Defaults to "https", which will work fine for fetching.
    """
    protocol = "https"
    try:
        url = subprocess.check_output(
            ["git", "remote", "get-url", "origin"], text=True
        ).strip()  # nosec:B607 B603
    except subprocess.CalledProcessError as err:
        raise RuntimeError(err)

    if url.startswith("git@") or url.startswith("ssh://"):
        protocol = "ssh"
    elif url.startswith("https://"):
        protocol = "https"
    return protocol


def get_primary_origin_branch() -> str:
    """
    Get the primary origin branch of the repository. Most likely "main" and defaults to "main".
    """
    default_branch = "main"
    try:
        ref_output = subprocess.check_output(
            ["git", "symbolic-ref", "refs/remotes/origin/HEAD"], text=True
        )  # nosec:B607 B603
    except subprocess.CalledProcessError as err:
        raise RuntimeError(err)

    ref = ref_output.strip()  # likely is "refs/remotes/origin/main"
    if ref == "":
        return default_branch

    spl = ref.split("/")
    if len(spl) == 0:
        return default_branch

    return spl[-1]


def ensure_upstream_set(git_protocol: str) -> None:
    """
    Ensure the upstream is set for the repository.
    """
    url = PANTHER_ANALYSIS_SSH_URL if git_protocol == "ssh" else PANTHER_ANALYSIS_HTTPS_URL

    # this returns non-zero code if the remote already exists, which is fine
    proc = subprocess.run(
        ["git", "remote", "add", REMOTE_UPSTREAM_NAME, url],
        check=False,
        capture_output=True,
    )  # nosec:B607 B603
    if proc.returncode == 0:
        logging.debug(f"Added {REMOTE_UPSTREAM_NAME} remote: {url}")


def panther_analysis_remote_upstream_branch() -> str:
    return f"{REMOTE_UPSTREAM_NAME}/{PANTHER_ANALYSIS_MAIN_BRANCH}"


def fetch_remotes(primary_origin_branch: str) -> None:
    """
    Fetch the latest from the local repo's origin and Panther Analysis' main.
    """
    remote_output = subprocess.check_output(["git", "remote", "-v"], text=True)  # nosec:B607 B603
    for line in remote_output.strip().split("\n"):
        if line.strip() == "":
            continue

        name, _, operation = line.strip().split()
        if operation == "(fetch)":
            if name == "origin":
                logging.debug(f"Fetching origin {primary_origin_branch}")
                subprocess.run(
                    ["git", "fetch", "origin", primary_origin_branch],
                    check=False,
                    capture_output=True,
                )  # nosec:B607 B603

                # if primary branch is develop, it is likely it copied it from PA but the user still uses a main branch
                if primary_origin_branch == "develop":
                    logging.debug("Fetching origin main")
                    # attempt to fetch origin main too just in case
                    subprocess.run(
                        ["git", "fetch", "origin", "main"], check=False, capture_output=True
                    )  # nosec:B607 B603
            elif name == REMOTE_UPSTREAM_NAME:
                logging.debug(f"Fetching {REMOTE_UPSTREAM_NAME} {PANTHER_ANALYSIS_MAIN_BRANCH}")
                subprocess.run(
                    ["git", "fetch", REMOTE_UPSTREAM_NAME, PANTHER_ANALYSIS_MAIN_BRANCH],
                    check=False,
                    capture_output=True,
                )  # nosec:B607 B603


def get_forked_panther_analysis_common_ancestor() -> str:
    """
    Get the merge base between the panther remote and the current branch, which is the common ancestor of the two branches.

    Returns:
        The merge base commit hash
    """
    ensure_upstream_set(get_git_protocol())
    fetch_remotes(get_primary_origin_branch())
    remote_branch = panther_analysis_remote_upstream_branch()
    ref = "HEAD"

    merge_base_output = subprocess.run(  # nosec:B607 B603
        ["git", "merge-base", remote_branch, ref], capture_output=True, text=True
    )
    if merge_base_output.returncode != 0:
        if merge_base_output.stderr == "":
            raise RuntimeError("Failed to find common ancestor")
        else:
            raise RuntimeError(f"Failed to get merge base: {merge_base_output.stderr}")
    output = merge_base_output.stdout.strip()
    if output == "":
        raise RuntimeError(f"No merge base found for 'git merge-base {remote_branch} {ref}'")

    logging.debug(f"Merge base found: {output}")
    return output


def get_file_at_commit(commit: str, file_path: pathlib.Path) -> bytes | None:
    """
    Get the contents of a file at a specific commit.

    Args:
        commit: The commit hash to get the file from.
        file_path: The path to the file.

    Returns:
        The contents of the file.
        None if the file does not exist.
    """
    args = [
        "git",
        "show",
        f"{commit}:{file_path}",
    ]

    proc = subprocess.run(
        args,
        text=True,
        check=False,
        capture_output=True,
    )  # nosec:B607 B603
    if proc.returncode != 0:
        logging.debug(proc.stderr)
        return None
    return proc.stdout.encode("utf-8")


def git_root() -> str:
    """
    Get the root of the git repo
    """
    global _git_root
    if _git_root is not None:
        return _git_root

    rev_parse = subprocess.run(  # nosec:B607 B603
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    )
    if rev_parse.returncode != 0:
        raise Exception(f"Failed to get git root: {rev_parse.stderr}")
    if rev_parse.stdout is None:
        raise Exception("Failed to get git root")
    _git_root = rev_parse.stdout.strip()
    return _git_root


def chdir_to_git_root() -> None:
    """
    Change the current working directory to the git root.
    """
    os.chdir(git_root())
