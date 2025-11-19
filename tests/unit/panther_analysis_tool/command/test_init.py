import pathlib
import subprocess

from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from panther_analysis_tool.command import init_project


def check_gitignore_content(gitignore_content: str) -> None:
    assert gitignore_content.count(".vscode/") == 1
    assert gitignore_content.count(".idea/") == 1
    assert gitignore_content.count(".cache") == 1
    assert gitignore_content.count(".panther_settings.*") == 1
    assert gitignore_content.count("__pycache__/") == 1
    assert gitignore_content.count("*.pyc") == 1
    assert gitignore_content.count("panther-analysis-*.zip") == 1


def test_init_project_with_no_gitignore(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.init_project.subprocess.run",
        return_value=subprocess.CompletedProcess(returncode=0, args=[]),
    )
    mock_print = mocker.patch("panther_analysis_tool.command.init_project.print")
    assert tmp_path.exists()
    monkeypatch.chdir(tmp_path)

    init_project.run(str(tmp_path))
    assert (tmp_path / ".gitignore").exists()
    assert ".gitignore file created" in mock_print.call_args_list[0][0][0]
    assert "Project is ready to use!" in mock_print.call_args_list[1][0][0]

    gitignore_content = (tmp_path / ".gitignore").read_text()
    check_gitignore_content(gitignore_content)


def test_init_project_with_gitignore(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture) -> None:
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
    assert "# something aleady here\n./stuff\n.vscode" in gitignore_content
    check_gitignore_content(gitignore_content)
