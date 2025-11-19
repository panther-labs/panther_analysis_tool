import pathlib
import re
import subprocess
from unittest import mock

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from panther_analysis_tool.constants import AutoAcceptOption
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


def test_merge_file(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "user.yml").write_text("user")
    (tmp_path / "base.yml").write_text("base")
    (tmp_path / "latest.yml").write_text("latest")

    run_mock = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[], stdout=b"merged"),
    )

    has_conflict, merged_contents = git_helpers.merge_file(
        user_file_path=tmp_path / "user.yml",
        base_file_path=tmp_path / "base.yml",
        latest_file_path=tmp_path / "latest.yml",
    )
    assert not has_conflict
    assert merged_contents == b"merged"
    run_mock.assert_called_once_with(
        [
            "git",
            "merge-file",
            "-p",
            "-L",
            "yours",
            "-L",
            "base",
            "-L",
            "panthers",
            str(tmp_path / "user.yml"),
            str(tmp_path / "base.yml"),
            str(tmp_path / "latest.yml"),
        ],
        check=False,
        capture_output=True,
    )


def test_merge_file_accept_yours(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "user.yml").write_text("user")
    (tmp_path / "base.yml").write_text("base")
    (tmp_path / "latest.yml").write_text("latest")

    run_mock = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[], stdout=b"merged"),
    )

    has_conflict, merged_contents = git_helpers.merge_file(
        user_file_path=tmp_path / "user.yml",
        base_file_path=tmp_path / "base.yml",
        latest_file_path=tmp_path / "latest.yml",
        auto_accept=AutoAcceptOption.YOURS,
    )
    assert not has_conflict
    assert merged_contents == b"merged"
    run_mock.assert_called_once_with(
        [
            "git",
            "merge-file",
            "-p",
            "--ours",
            "-L",
            "yours",
            "-L",
            "base",
            "-L",
            "panthers",
            str(tmp_path / "user.yml"),
            str(tmp_path / "base.yml"),
            str(tmp_path / "latest.yml"),
        ],
        check=False,
        capture_output=True,
    )


def test_merge_file_accept_panthers(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "user.yml").write_text("user")
    (tmp_path / "base.yml").write_text("base")
    (tmp_path / "latest.yml").write_text("latest")

    run_mock = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[], stdout=b"merged"),
    )

    has_conflict, merged_contents = git_helpers.merge_file(
        user_file_path=tmp_path / "user.yml",
        base_file_path=tmp_path / "base.yml",
        latest_file_path=tmp_path / "latest.yml",
        auto_accept=AutoAcceptOption.PANTHERS,
    )
    assert not has_conflict
    assert merged_contents == b"merged"
    run_mock.assert_called_once_with(
        [
            "git",
            "merge-file",
            "-p",
            "--theirs",
            "-L",
            "yours",
            "-L",
            "base",
            "-L",
            "panthers",
            str(tmp_path / "user.yml"),
            str(tmp_path / "base.yml"),
            str(tmp_path / "latest.yml"),
        ],
        check=False,
        capture_output=True,
    )
