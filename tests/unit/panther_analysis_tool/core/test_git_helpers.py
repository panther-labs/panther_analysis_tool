import pathlib
import re
import subprocess
from unittest import mock

import pytest
from _pytest.monkeypatch import MonkeyPatch

from panther_analysis_tool.core import git_helpers


def test_panther_analysis_release_url() -> None:
    assert (
        git_helpers.panther_analysis_release_url()
        == "https://api.github.com/repos/panther-labs/panther-analysis/releases/latest"
    )


def test_panther_analysis_latest_release_commit() -> None:
    with mock.patch("requests.get", return_value=mock.Mock(json=lambda: {"tag_name": "v7.7.7"})):
        assert re.match(
            git_helpers.panther_analysis_latest_release_commit(),
            "v7.7.7",
        )


def test_clone_panther_analysis(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    with (
        mock.patch("shutil.rmtree", return_value=None),
        mock.patch(
            "subprocess.run", return_value=subprocess.CompletedProcess(returncode=0, args=[])
        ) as mock_subprocess_run,
    ):
        monkeypatch.chdir(tmp_path)
        git_helpers.CLONED_REPO_PATH.mkdir(parents=True, exist_ok=True)
        git_helpers.clone_panther_analysis("main")
        assert mock_subprocess_run.call_count == 1


def test_clone_panther_analysis_with_commit(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    with (
        mock.patch("shutil.rmtree", return_value=None),
        mock.patch(
            "subprocess.run", return_value=subprocess.CompletedProcess(returncode=0, args=[])
        ) as mock_subprocess_run,
    ):
        monkeypatch.chdir(tmp_path)
        git_helpers.CLONED_REPO_PATH.mkdir(parents=True, exist_ok=True)
        git_helpers.clone_panther_analysis("main", "v7.7.7")
        assert mock_subprocess_run.call_count == 2


def test_clone_panther_analysis_subproccess_fails(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    with (
        mock.patch("shutil.rmtree", return_value=None),
        mock.patch(
            "subprocess.run", return_value=subprocess.CompletedProcess(returncode=1, args=[])
        ),
    ):
        monkeypatch.chdir(tmp_path)
        git_helpers.CLONED_REPO_PATH.mkdir(parents=True, exist_ok=True)

        with pytest.raises(RuntimeError):
            git_helpers.clone_panther_analysis("main", "v7.7.7")


def test_get_panther_analysis_file_contents() -> None:
    with mock.patch("requests.get", return_value=mock.Mock(text="stuff")):
        result = git_helpers.get_panther_analysis_file_contents(
            "f40e2829304b30eacdb51f6d9023c89fa8f19b58",
            "rules/atlassian_rules/user_logged_in_as_user.yml",
        )
        assert result == "stuff"
