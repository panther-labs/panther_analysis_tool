import pathlib
import subprocess

from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from panther_analysis_tool.command import init_project
from panther_analysis_tool.constants import PAT_ROOT_FILE_NAME
from panther_analysis_tool.core import git_helpers


def test_init_project_with_no_gitignore(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.init_project.analysis_cache.update_with_latest_panther_analysis",
        return_value=None,
    )
    mocker.patch(
        "panther_analysis_tool.command.init_project.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[]),
    )
    mocker.patch(
        "panther_analysis_tool.command.init_project.git_helpers.git_root", return_value=tmp_path
    )
    mock_print = mocker.patch("panther_analysis_tool.command.init_project.print")
    assert tmp_path.exists()
    monkeypatch.chdir(tmp_path)

    init_project.run(str(tmp_path))
    assert (tmp_path / ".gitignore").exists()
    assert ".gitignore file created" in mock_print.call_args_list[0][0][0]
    assert "Project is ready to use!" in mock_print.call_args_list[1][0][0]

    gitignore_content = (tmp_path / ".gitignore").read_text()
    assert (
        gitignore_content
        == """# Panther settings
.panther_settings.*

# Python
__pycache__/
*.pyc
.mypy_cache/
.pytest_cache/

# Panther
panther-analysis-*.zip
.cache/

# IDEs
.vscode/
.idea/

"""
    )


def test_init_project_with_gitignore(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.init_project.analysis_cache.update_with_latest_panther_analysis",
        return_value=None,
    )
    mocker.patch(
        "panther_analysis_tool.command.init_project.git_helpers.git_root", return_value=tmp_path
    )
    monkeypatch.chdir(tmp_path)
    mock_subprocess_run = mocker.patch(
        "panther_analysis_tool.command.init_project.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[]),
    )
    mock_print = mocker.patch("panther_analysis_tool.command.init_project.print")

    gitignore_path = tmp_path / ".gitignore"
    gitignore_path.touch()
    gitignore_path.write_text("# something aleady here\n./stuff\n.vscode/\nstuff")

    init_project.run(str(tmp_path))
    assert gitignore_path.exists()
    assert ".gitignore file created" not in mock_print.call_args_list[0][0][0]
    assert "Project is ready to use!" in mock_print.call_args_list[0][0][0]

    gitignore_content = gitignore_path.read_text()
    assert (
        gitignore_content
        == """# something aleady here
./stuff
.vscode/
stuff

# Panther settings
.panther_settings.*

# Python
__pycache__/
*.pyc
.mypy_cache/
.pytest_cache/

# Panther
panther-analysis-*.zip
.cache/

# IDEs
.idea/

"""
    )


def test_init_project_with_gitignore_end_with_newline(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.init_project.analysis_cache.update_with_latest_panther_analysis",
        return_value=None,
    )
    mocker.patch(
        "panther_analysis_tool.command.init_project.git_helpers.git_root", return_value=tmp_path
    )
    monkeypatch.chdir(tmp_path)
    mocker.patch(
        "panther_analysis_tool.command.init_project.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[]),
    )
    mock_print = mocker.patch("panther_analysis_tool.command.init_project.print")

    gitignore_path = tmp_path / ".gitignore"
    gitignore_path.touch()
    gitignore_path.write_text("# something aleady here\n./stuff\n.vscode/\nstuff\n")

    init_project.run(str(tmp_path))
    assert gitignore_path.exists()
    assert ".gitignore file created" not in mock_print.call_args_list[0][0][0]
    assert "Project is ready to use!" in mock_print.call_args_list[0][0][0]

    gitignore_content = gitignore_path.read_text()
    assert (
        gitignore_content
        == """# something aleady here
./stuff
.vscode/
stuff

# Panther settings
.panther_settings.*

# Python
__pycache__/
*.pyc
.mypy_cache/
.pytest_cache/

# Panther
panther-analysis-*.zip
.cache/

# IDEs
.idea/

"""
    )


def test_init_project_with_pat_root(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    # Create a fake git root that's different from tmp_path (within tmp_path for cleanup)
    fake_git_root = tmp_path / "fake_git_root"
    fake_git_root.mkdir(exist_ok=True)

    mocker.patch(
        "panther_analysis_tool.command.init_project.analysis_cache.update_with_latest_panther_analysis",
        return_value=None,
    )
    mocker.patch(
        "panther_analysis_tool.command.init_project.git_helpers.git_root",
        return_value=fake_git_root,
    )
    mocker.patch(
        "panther_analysis_tool.command.init_project.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[]),
    )
    mock_print = mocker.patch("panther_analysis_tool.command.init_project.print")
    monkeypatch.chdir(tmp_path)

    init_project.run(str(tmp_path))
    assert (tmp_path / PAT_ROOT_FILE_NAME).exists()

    # Check that .gitignore file created message is printed first
    assert ".gitignore file created" in mock_print.call_args_list[0][0][0]

    # Check that "Project is ready to use!" is printed
    assert "Project is ready to use!" in mock_print.call_args_list[1][0][0]

    # Check that the .pat-root creation message is printed (contains ".pat-root")
    assert PAT_ROOT_FILE_NAME in mock_print.call_args_list[2][0][0]

    pat_root_content = (tmp_path / PAT_ROOT_FILE_NAME).read_text()
    assert (
        pat_root_content
        == "# File created by Panther Analysis Tool to track the root of your Panther project. Please commit this file and do not delete it.\n"
    )

    # Verify .gitignore was created at git root, not at working_dir
    assert (fake_git_root / ".gitignore").exists()
    assert not (tmp_path / ".gitignore").exists()


def test_init_project_updates_gitignore_at_git_root_not_working_dir(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """
    Test that when running init from a subdirectory (monorepo scenario),
    only the .gitignore at git root is updated, not any .gitignore in the working directory.

    This test verifies that setup_git_ignore uses git_root() to ensure only the git root's
    .gitignore is modified.
    """
    git_root = tmp_path
    working_dir = git_root / "pa" / "subdirectory"
    working_dir.mkdir(parents=True, exist_ok=True)

    # Create a .gitignore in the working directory that should NOT be touched
    working_dir_gitignore = working_dir / ".gitignore"
    working_dir_gitignore.write_text("# This should not be modified\nlocal_stuff/\n")

    mocker.patch(
        "panther_analysis_tool.command.init_project.analysis_cache.update_with_latest_panther_analysis",
        return_value=None,
    )
    mocker.patch(
        "panther_analysis_tool.command.init_project.git_helpers.git_root", return_value=git_root
    )
    mocker.patch(
        "panther_analysis_tool.command.init_project.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[]),
    )
    monkeypatch.chdir(working_dir)

    init_project.run(str(working_dir))

    # Verify git root .gitignore was created/updated
    git_root_gitignore = git_root / ".gitignore"
    assert git_root_gitignore.exists()
    assert ".cache/" in git_root_gitignore.read_text()

    # Verify working directory .gitignore was NOT modified
    assert working_dir_gitignore.exists()
    working_dir_content = working_dir_gitignore.read_text()
    assert working_dir_content == "# This should not be modified\nlocal_stuff/\n"
    assert ".cache/" not in working_dir_content


def test_init_project_updates_existing_gitignore_at_git_root_not_working_dir(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """
    Test that when running init from a subdirectory with existing .gitignore at git root,
    only the git root .gitignore is updated, not any .gitignore in the working directory.

    This test verifies that setup_git_ignore uses git_root() to ensure only the git root's
    .gitignore is modified.
    """
    git_root = tmp_path
    working_dir = git_root / "pa" / "subdirectory"
    working_dir.mkdir(parents=True, exist_ok=True)

    # Create .gitignore at git root that SHOULD be updated
    git_root_gitignore = git_root / ".gitignore"
    git_root_gitignore.write_text("# Existing git root content\nold_stuff/\n")

    # Create a .gitignore in the working directory that should NOT be touched
    working_dir_gitignore = working_dir / ".gitignore"
    working_dir_gitignore.write_text("# This should not be modified\nlocal_stuff/\n")

    mocker.patch(
        "panther_analysis_tool.command.init_project.analysis_cache.update_with_latest_panther_analysis",
        return_value=None,
    )
    mocker.patch(
        "panther_analysis_tool.command.init_project.git_helpers.git_root", return_value=git_root
    )
    mocker.patch(
        "panther_analysis_tool.command.init_project.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[]),
    )
    monkeypatch.chdir(working_dir)

    init_project.run(str(working_dir))

    # Verify git root .gitignore was updated with Panther entries
    git_root_content = git_root_gitignore.read_text()
    assert "# Existing git root content" in git_root_content
    assert "old_stuff/" in git_root_content
    assert ".cache/" in git_root_content
    assert "# Panther" in git_root_content

    # Verify working directory .gitignore was NOT modified
    assert working_dir_gitignore.exists()
    working_dir_content = working_dir_gitignore.read_text()
    assert working_dir_content == "# This should not be modified\nlocal_stuff/\n"
    assert ".cache/" not in working_dir_content
    assert "# Panther" not in working_dir_content
