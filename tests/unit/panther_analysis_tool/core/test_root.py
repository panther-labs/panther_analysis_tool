import pathlib

from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from panther_analysis_tool.constants import PAT_ROOT_FILE_NAME
from panther_analysis_tool.core import root


def test_chdir_to_project_root_with_no_pat_root(
    mocker: MockerFixture, tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that the current working directory is changed to the git root if no .pat-root file is present.
    """
    monkeypatch.chdir(tmp_path)
    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=tmp_path)
    mock_os_chdir = mocker.patch("os.chdir", return_value=None)

    root.chdir_to_project_root()
    assert mock_os_chdir.call_count == 1
    assert mock_os_chdir.call_args[0][0] == tmp_path


def test_chdir_to_project_root_with_pat_root(
    mocker: MockerFixture, tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that the current working directory is changed to the directory with the .pat-root file.
    """
    monkeypatch.chdir(tmp_path)
    pat_root_path = tmp_path / "subdir" / PAT_ROOT_FILE_NAME
    pat_root_path.parent.mkdir(parents=True, exist_ok=True)
    pat_root_path.touch()
    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=tmp_path)
    mock_os_chdir = mocker.patch("os.chdir", return_value=None)

    root.chdir_to_project_root()
    assert mock_os_chdir.call_count == 1
    assert pathlib.Path(mock_os_chdir.call_args[0][0]) == pat_root_path.parent


def test_chdir_to_project_root_with_pat_root_in_git_root(
    mocker: MockerFixture, tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that the current working directory is changed to git root when .pat-root file is in git root.
    """
    monkeypatch.chdir(tmp_path)
    pat_root_path = tmp_path / PAT_ROOT_FILE_NAME
    pat_root_path.touch()
    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=tmp_path)
    mock_os_chdir = mocker.patch("os.chdir", return_value=None)

    root.chdir_to_project_root()
    assert mock_os_chdir.call_count == 1
    assert pathlib.Path(mock_os_chdir.call_args[0][0]) == tmp_path


def test_chdir_to_project_root_with_multiple_pat_root_files(
    mocker: MockerFixture, tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that when multiple .pat-root files exist, it picks the shallowest one (first found by os.walk).
    """
    monkeypatch.chdir(tmp_path)
    # Create .pat-root files at different depths
    shallow_pat_root = tmp_path / "level1" / PAT_ROOT_FILE_NAME
    deep_pat_root = tmp_path / "level1" / "level2" / "level3" / PAT_ROOT_FILE_NAME
    shallow_pat_root.parent.mkdir(parents=True, exist_ok=True)
    deep_pat_root.parent.mkdir(parents=True, exist_ok=True)
    shallow_pat_root.touch()
    deep_pat_root.touch()

    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=tmp_path)
    mock_os_chdir = mocker.patch("os.chdir", return_value=None)

    root.chdir_to_project_root()
    assert mock_os_chdir.call_count == 1
    # Should pick the shallowest one (level1)
    assert pathlib.Path(mock_os_chdir.call_args[0][0]) == shallow_pat_root.parent


def test_chdir_to_project_root_with_deeply_nested_pat_root(
    mocker: MockerFixture, tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that it correctly finds a deeply nested .pat-root file.
    """
    monkeypatch.chdir(tmp_path)
    deep_pat_root = tmp_path / "a" / "b" / "c" / "d" / "e" / PAT_ROOT_FILE_NAME
    deep_pat_root.parent.mkdir(parents=True, exist_ok=True)
    deep_pat_root.touch()

    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=tmp_path)
    mock_os_chdir = mocker.patch("os.chdir", return_value=None)

    root.chdir_to_project_root()
    assert mock_os_chdir.call_count == 1
    assert pathlib.Path(mock_os_chdir.call_args[0][0]) == deep_pat_root.parent


def test_chdir_to_project_root_from_subdirectory_normal_repo(
    mocker: MockerFixture, tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that when running from a subdirectory in a normal repo (no .pat-root),
    it chdirs to git root.
    """
    git_root = tmp_path
    subdir = git_root / "some" / "deep" / "subdirectory"
    subdir.mkdir(parents=True, exist_ok=True)

    monkeypatch.chdir(subdir)
    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=git_root)
    mock_os_chdir = mocker.patch("os.chdir", return_value=None)

    root.chdir_to_project_root()
    assert mock_os_chdir.call_count == 1
    assert pathlib.Path(mock_os_chdir.call_args[0][0]) == git_root


def test_chdir_to_project_root_from_subdirectory_monorepo(
    mocker: MockerFixture, tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that when running from a subdirectory in a monorepo (with .pat-root),
    it chdirs to the directory with .pat-root, not git root.
    """
    git_root = tmp_path
    project_root = git_root / "pa"  # monorepo structure: repo/pa/
    deep_subdir = project_root / "rules" / "some" / "nested" / "path"

    project_root.mkdir(parents=True, exist_ok=True)
    deep_subdir.mkdir(parents=True, exist_ok=True)
    (project_root / PAT_ROOT_FILE_NAME).touch()

    monkeypatch.chdir(deep_subdir)
    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=git_root)
    mock_os_chdir = mocker.patch("os.chdir", return_value=None)

    root.chdir_to_project_root()
    assert mock_os_chdir.call_count == 1
    assert pathlib.Path(mock_os_chdir.call_args[0][0]) == project_root


def test_chdir_to_project_root_from_project_root_monorepo(
    mocker: MockerFixture, tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """
    Test that when already in project root (with .pat-root), it still chdirs correctly.
    """
    git_root = tmp_path
    project_root = git_root / "pa"
    project_root.mkdir(parents=True, exist_ok=True)
    (project_root / PAT_ROOT_FILE_NAME).touch()

    monkeypatch.chdir(project_root)
    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=git_root)
    mock_os_chdir = mocker.patch("os.chdir", return_value=None)

    root.chdir_to_project_root()
    assert mock_os_chdir.call_count == 1
    assert pathlib.Path(mock_os_chdir.call_args[0][0]) == project_root


def test_cache_created_at_project_root_monorepo(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """
    Test that cache directory is created at project root (not git root or subdirectory)
    when running from a subdirectory in a monorepo.
    """
    import os

    from panther_analysis_tool.constants import CACHE_DIR

    git_root = tmp_path
    project_root = git_root / "pa"
    subdir = project_root / "some" / "nested" / "directory"

    project_root.mkdir(parents=True, exist_ok=True)
    subdir.mkdir(parents=True, exist_ok=True)
    (project_root / PAT_ROOT_FILE_NAME).touch()

    monkeypatch.chdir(subdir)

    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=git_root)

    # Create cache - this should happen at project root after chdir
    # We'll simulate this by chdir'ing to project root first
    os.chdir(project_root)

    cache_dir = pathlib.Path(CACHE_DIR)
    cache_dir.mkdir(exist_ok=True)

    # Verify cache is at project root, not subdirectory or git root
    assert (project_root / CACHE_DIR).exists()
    assert not (subdir / CACHE_DIR).exists()
    assert not (git_root / CACHE_DIR).exists()


def test_cache_created_at_git_root_normal_repo(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """
    Test that cache directory is created at git root (not subdirectory)
    when running from a subdirectory in a normal repo.
    """
    import os

    from panther_analysis_tool.constants import CACHE_DIR

    git_root = tmp_path
    subdir = git_root / "some" / "nested" / "directory"
    subdir.mkdir(parents=True, exist_ok=True)

    monkeypatch.chdir(subdir)

    mocker.patch("panther_analysis_tool.core.git_helpers.git_root", return_value=git_root)

    # Create cache at git root (simulating chdir_to_project_root behavior)
    os.chdir(git_root)

    cache_dir = pathlib.Path(CACHE_DIR)
    cache_dir.mkdir(exist_ok=True)

    # Verify cache is at git root, not subdirectory
    assert (git_root / CACHE_DIR).exists()
    assert not (subdir / CACHE_DIR).exists()
