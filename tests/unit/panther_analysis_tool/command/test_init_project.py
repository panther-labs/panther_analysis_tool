import pathlib
import subprocess

from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from panther_analysis_tool.command import init_project


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
    mocker.patch("panther_analysis_tool.command.init_project.git_helpers.chdir_to_git_root")
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
    mocker.patch("panther_analysis_tool.command.init_project.git_helpers.chdir_to_git_root")
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
    mocker.patch("panther_analysis_tool.command.init_project.git_helpers.chdir_to_git_root")
    monkeypatch.chdir(tmp_path)
    mock_subprocess_run = mocker.patch(
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
