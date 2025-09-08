import subprocess

PANTHER_HTTPS_PATH = "https://github.com/panther-labs/panther-analysis.git"
PANTHER_SSH_PATH = "git@github.com:panther-labs/panther-analysis.git"
PANTHER_PRIMARY_BRANCH = "main"


class GitManager:
    def __init__(self):
        self._panther_remote = None
        self._git_root = None

    def panther_latest_release_commit(self) -> str:
        """
        Get the panther commit hash
        """
        return f"{self.panther_remote()}/{PANTHER_PRIMARY_BRANCH}"

    def panther_remote(self) -> str:
        if self._panther_remote is not None:
            return self._panther_remote

        panther_remote_output = subprocess.run(
            ["git", "remote", "-v"], capture_output=True, text=True
        )
        if panther_remote_output.returncode != 0:
            raise Exception(f"Failed to get panther remote: {panther_remote_output.stderr}")
        panther_remote_output = panther_remote_output.stdout
        for line in panther_remote_output.split("\n"):
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
        merge_base_output = subprocess.run(
            ["git", "merge-base", panther_commit, branch], capture_output=True, text=True
        )
        if merge_base_output.returncode != 0:
            if "Not a valid object name" in merge_base_output.stderr:
                # need to fetch the panther remote
                subprocess.run(["git", "fetch", self.panther_remote()], check=True)
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

        self._git_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
        ).stdout.strip()
        return self._git_root
