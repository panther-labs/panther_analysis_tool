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


def test_get_git_protocol(mocker: MockerFixture) -> None:
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.check_output",
        return_value="https://github.com/panther-labs/panther-analysis.git",
    )
    assert git_helpers.get_git_protocol() == "https"
    mock_check_output.assert_called_once_with(["git", "remote", "get-url", "origin"], text=True)


def test_get_git_protocol_ssh(mocker: MockerFixture) -> None:
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.check_output",
        return_value="git@github.com:panther-labs/panther-analysis.git",
    )
    assert git_helpers.get_git_protocol() == "ssh"
    mock_check_output.assert_called_once_with(["git", "remote", "get-url", "origin"], text=True)


def test_get_primary_origin_branch(mocker: MockerFixture) -> None:
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.check_output",
        return_value="refs/remotes/origin/main",
    )
    assert git_helpers.get_primary_origin_branch() == "main"
    mock_check_output.assert_called_once_with(
        ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
        text=True,
        stderr=subprocess.DEVNULL,
    )


def test_get_primary_origin_branch_develop(mocker: MockerFixture) -> None:
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.check_output",
        return_value="refs/remotes/origin/develop",
    )
    assert git_helpers.get_primary_origin_branch() == "develop"
    mock_check_output.assert_called_once_with(
        ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
        text=True,
        stderr=subprocess.DEVNULL,
    )


def test_get_primary_origin_branch_remote_fallback(mocker: MockerFixture) -> None:
    """Test that when local symbolic ref fails, it falls back to remote query."""
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.check_output",
        side_effect=[
            subprocess.CalledProcessError(1, "git", stderr="error"),  # First call fails
            "ref: refs/heads/main	HEAD\nabc123	HEAD",  # Remote query succeeds
        ],
    )
    assert git_helpers.get_primary_origin_branch() == "main"
    assert mock_check_output.call_count == 2
    mock_check_output.assert_any_call(
        ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    mock_check_output.assert_any_call(
        ["git", "ls-remote", "--symref", "origin", "HEAD"],
        text=True,
        stderr=subprocess.DEVNULL,
    )


def test_get_primary_origin_branch_remote_fallback_develop(mocker: MockerFixture) -> None:
    """Test remote fallback with develop branch."""
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.check_output",
        side_effect=[
            subprocess.CalledProcessError(1, "git", stderr="error"),  # First call fails
            "ref: refs/heads/develop	HEAD\nabc123	HEAD",  # Remote query succeeds
        ],
    )
    assert git_helpers.get_primary_origin_branch() == "develop"
    assert mock_check_output.call_count == 2


def test_get_primary_origin_branch_default(mocker: MockerFixture) -> None:
    """Test that when both local and remote queries fail, it defaults to main."""
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.check_output",
        side_effect=[
            subprocess.CalledProcessError(1, "git", stderr="error"),  # Local fails
            subprocess.CalledProcessError(1, "git", stderr="error"),  # Remote fails
        ],
    )
    assert git_helpers.get_primary_origin_branch() == "main"
    assert mock_check_output.call_count == 2
    mock_check_output.assert_any_call(
        ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    mock_check_output.assert_any_call(
        ["git", "ls-remote", "--symref", "origin", "HEAD"],
        text=True,
        stderr=subprocess.DEVNULL,
    )


def test_ensure_upstream_set_ssh(mocker: MockerFixture) -> None:
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[]),
    )
    git_helpers.ensure_upstream_set("ssh")
    mock_check_output.assert_called_once_with(
        ["git", "remote", "add", "upstream", "git@github.com:panther-labs/panther-analysis.git"],
        check=False,
        capture_output=True,
    )


def test_ensure_upstream_set_https(mocker: MockerFixture) -> None:
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[]),
    )
    git_helpers.ensure_upstream_set("https")
    mock_check_output.assert_called_once_with(
        [
            "git",
            "remote",
            "add",
            "upstream",
            "https://github.com/panther-labs/panther-analysis.git",
        ],
        check=False,
        capture_output=True,
    )


def test_panther_analysis_remote_upstream_branch(mocker: MockerFixture) -> None:
    assert git_helpers.panther_analysis_remote_upstream_branch() == "upstream/main"


def test_fetch_remotes(mocker: MockerFixture) -> None:
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.check_output",
        return_value="""
origin https://github.com/panther-labs/panther-analysis.git (fetch)
origin https://github.com/panther-labs/panther-analysis.git (push)
upstream https://github.com/panther-labs/panther-analysis.git (fetch)
upstream https://github.com/panther-labs/panther-analysis.git (push)
""",
    )
    mock_run = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[]),
    )
    git_helpers.fetch_remotes("main")
    mock_check_output.assert_called_once_with(["git", "remote", "-v"], text=True)
    mock_run.assert_any_call(["git", "fetch", "origin", "main"], check=False, capture_output=True)
    mock_run.assert_any_call(["git", "fetch", "upstream", "main"], check=False, capture_output=True)


def test_fetch_remotes_with_develop_branch(mocker: MockerFixture) -> None:
    """Test that when primary branch is develop, it also attempts to fetch main."""
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.check_output",
        return_value="""
origin https://github.com/panther-labs/panther-analysis.git (fetch)
origin https://github.com/panther-labs/panther-analysis.git (push)
upstream https://github.com/panther-labs/panther-analysis.git (fetch)
upstream https://github.com/panther-labs/panther-analysis.git (push)
""",
    )
    mock_run = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[]),
    )
    git_helpers.fetch_remotes("develop")
    mock_check_output.assert_called_once_with(["git", "remote", "-v"], text=True)
    mock_run.assert_any_call(
        ["git", "fetch", "origin", "develop"], check=False, capture_output=True
    )
    mock_run.assert_any_call(["git", "fetch", "origin", "main"], check=False, capture_output=True)
    mock_run.assert_any_call(["git", "fetch", "upstream", "main"], check=False, capture_output=True)


def test_fetch_remotes_handles_fetch_errors(mocker: MockerFixture) -> None:
    """Test that fetch errors are handled gracefully without raising exceptions."""
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.check_output",
        return_value="""
origin https://github.com/panther-labs/panther-analysis.git (fetch)
origin https://github.com/panther-labs/panther-analysis.git (push)
upstream https://github.com/panther-labs/panther-analysis.git (fetch)
upstream https://github.com/panther-labs/panther-analysis.git (push)
""",
    )
    mock_run = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.run",
        side_effect=[
            subprocess.CompletedProcess(
                returncode=1, args=[], stderr=b"fetch error"
            ),  # origin fetch fails
            subprocess.CompletedProcess(returncode=0, args=[]),  # upstream fetch succeeds
        ],
    )
    # Should not raise an exception
    git_helpers.fetch_remotes("main")
    mock_check_output.assert_called_once_with(["git", "remote", "-v"], text=True)
    assert mock_run.call_count == 2
    mock_run.assert_any_call(["git", "fetch", "origin", "main"], check=False, capture_output=True)
    mock_run.assert_any_call(["git", "fetch", "upstream", "main"], check=False, capture_output=True)


def test_get_forked_panther_analysis_common_ancestor(mocker: MockerFixture) -> None:
    """Test get_forked_panther_analysis_common_ancestor with proper mocking of all subprocess calls."""
    # Mock get_git_protocol() calls
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.check_output",
        side_effect=[
            "https://github.com/panther-labs/panther-analysis.git",  # get_git_protocol()
            "refs/remotes/origin/main",  # get_primary_origin_branch() - local symbolic ref
            """
origin https://github.com/panther-labs/panther-analysis.git (fetch)
origin https://github.com/panther-labs/panther-analysis.git (push)
upstream https://github.com/panther-labs/panther-analysis.git (fetch)
upstream https://github.com/panther-labs/panther-analysis.git (push)
""",  # fetch_remotes() - remote list
        ],
    )
    # Mock subprocess.run calls for fetch_remotes and merge-base
    mock_run = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.run",
        side_effect=[
            subprocess.CompletedProcess(
                returncode=0, args=[]
            ),  # ensure_upstream_set() - remote add (may fail, that's ok)
            subprocess.CompletedProcess(returncode=0, args=[]),  # fetch_remotes() - fetch origin
            subprocess.CompletedProcess(returncode=0, args=[]),  # fetch_remotes() - fetch upstream
            subprocess.CompletedProcess(
                returncode=0, args=[], stdout="f40e2829304b30eacdb51f6d9023c89fa8f19b58"
            ),  # merge-base
        ],
    )
    assert (
        git_helpers.get_forked_panther_analysis_common_ancestor()
        == "f40e2829304b30eacdb51f6d9023c89fa8f19b58"
    )
    # Verify that get_git_protocol was called
    mock_check_output.assert_any_call(["git", "remote", "get-url", "origin"], text=True)
    # Verify that get_primary_origin_branch was called
    mock_check_output.assert_any_call(
        ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    # Verify that merge-base was called
    mock_run.assert_any_call(
        ["git", "merge-base", "upstream/main", "HEAD"],
        capture_output=True,
        text=True,
    )


def test_get_file_at_commit(mocker: MockerFixture) -> None:
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[], stdout="stuff"),
    )
    commit = "f40e2829304b30eacdb51f6d9023c89fa8f19b58"
    file_path = pathlib.Path("rules/atlassian_rules/user_logged_in_as_user.yml")
    assert git_helpers.get_file_at_commit(commit, file_path) == b"stuff"
    mock_check_output.assert_called_once_with(
        ["git", "show", f"{commit}:{file_path}"],
        text=True,
        check=False,
        capture_output=True,
    )


def test_get_file_at_commit_none(mocker: MockerFixture) -> None:
    mock_check_output = mocker.patch(
        "panther_analysis_tool.core.git_helpers.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=1, args=[], stderr="error"),
    )
    commit = "f40e2829304b30eacdb51f6d9023c89fa8f19b58"
    file_path = pathlib.Path("rules/atlassian_rules/user_logged_in_as_user.yml")
    assert git_helpers.get_file_at_commit(commit, file_path) is None
    mock_check_output.assert_called_once_with(
        ["git", "show", f"{commit}:{file_path}"],
        text=True,
        check=False,
        capture_output=True,
    )
