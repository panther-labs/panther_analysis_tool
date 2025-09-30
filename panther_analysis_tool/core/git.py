import subprocess  # nosec:B404
from typing import Optional

PANTHER_HTTPS_PATH = "https://github.com/panther-labs/panther-analysis.git"
PANTHER_SSH_PATH = "git@github.com:panther-labs/panther-analysis.git"
PANTHER_PRIMARY_BRANCH = "main"


class GitManager:
    def __init__(self) -> None:
        self._panther_remote: Optional[str] = None
        self._git_root: Optional[str] = None

    def panther_latest_release_commit(self) -> str:
        """
        Get the panther commit hash
        """
        return f"{self.panther_remote()}/{PANTHER_PRIMARY_BRANCH}"

    def panther_remote(self) -> str:
        if self._panther_remote is not None:
            return self._panther_remote

        panther_remote_output = subprocess.run(  # nosec:B607 B603
            ["git", "remote", "-v"], capture_output=True, text=True
        )
        if panther_remote_output.returncode != 0:
            raise Exception(f"Failed to get panther remote: {panther_remote_output.stderr}")
        panther_remote_stdout = panther_remote_output.stdout
        for line in panther_remote_stdout.split("\n"):
            name, url, operation = line.strip().split()
            if url in [PANTHER_HTTPS_PATH, PANTHER_SSH_PATH] and operation == "(fetch)":
                self._panther_remote = name
                return name
        raise Exception("Panther remote not found")

    def merge_base(self, branch: str) -> str:
        """
        Get the merge base between the panther remote and the current branch

        Args:
            branch: The branch to get the merge base from

        Returns:
            The merge base commit hash
        """
        panther_commit = self.panther_latest_release_commit()
        merge_base_output = subprocess.run(  # nosec:B607 B603
            ["git", "merge-base", panther_commit, branch], capture_output=True, text=True
        )
        if merge_base_output.returncode != 0:
            if "Not a valid object name" in merge_base_output.stderr:
                # need to fetch the panther remote
                subprocess.run(
                    ["git", "fetch", self.panther_remote()], check=True
                )  # nosec:B607 B603
            elif merge_base_output.stderr == "":
                raise Exception(f"Failed to find common ancestor:")
            else:
                raise Exception(f"Failed to get merge base: {merge_base_output.stderr}")
        output = merge_base_output.stdout.strip()
        if output == "":
            raise Exception(f"No merge base found for {branch} and {panther_commit}")
        return output

    def git_root(self) -> str:
        """
        Get the root of the git repo
        """
        if self._git_root is not None:
            return self._git_root

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
        self._git_root = rev_parse.stdout.strip()
        return self._git_root
