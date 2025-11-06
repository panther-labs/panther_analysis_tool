import pathlib

import pytest
from pytest_mock import MockerFixture

from panther_analysis_tool import constants
from panther_analysis_tool.core import file_editor


@pytest.mark.parametrize(
    "editor_cmd",
    [
        "idea",
        "pycharm",
        "webstorm",
        "phpstorm",
        "rubymine",
        "clion",
        "goland",
        "rider",
        "appcode",
        "rustrover",
        "dataspell",
    ],
)
def test_merge_files_in_jetbrains_editor(
    tmp_path: pathlib.Path, mocker: MockerFixture, editor_cmd: str
) -> None:
    mock_run = mocker.patch(
        "panther_analysis_tool.core.file_editor.subprocess.run", return_value=None
    )

    files = file_editor.MergeableFiles(
        users_file=tmp_path / "users_file.py",
        base_file=tmp_path / "base_file.py",
        panthers_file=tmp_path / "panthers_file.py",
        output_file=tmp_path / "output_file.py",
        premerged_file=tmp_path / "premerged_file.py",
    )
    files.users_file.touch()
    files.base_file.touch()
    files.panthers_file.touch()
    files.output_file.touch()
    files.premerged_file.touch()

    async_edit = file_editor.merge_files_in_editor(files, editor_cmd)
    assert async_edit
    mock_run.assert_called_once_with(
        [
            editor_cmd,
            "merge",
            str(tmp_path / "users_file.py"),
            str(tmp_path / "panthers_file.py"),
            str(tmp_path / "base_file.py"),
            str(tmp_path / "output_file.py"),
        ],
        check=True,
    )


@pytest.mark.parametrize("editor_cmd", ["code", "cursor", "emacs", "nano"])
def test_merge_files_in_other_editor(
    tmp_path: pathlib.Path, mocker: MockerFixture, editor_cmd: str
) -> None:
    mock_run = mocker.patch(
        "panther_analysis_tool.core.file_editor.subprocess.run", return_value=None
    )

    files = file_editor.MergeableFiles(
        users_file=tmp_path / "users_file.py",
        base_file=tmp_path / "base_file.py",
        panthers_file=tmp_path / "panthers_file.py",
        output_file=tmp_path / "output_file.py",
        premerged_file=tmp_path / "premerged_file.py",
    )
    files.users_file.touch()
    files.base_file.touch()
    files.panthers_file.touch()
    files.output_file.touch()
    files.premerged_file.touch()

    async_edit = file_editor.merge_files_in_editor(files, editor_cmd)
    assert async_edit
    mock_run.assert_called_once_with([editor_cmd, str(tmp_path / "premerged_file.py")], check=True)


@pytest.mark.parametrize("editor_cmd", ["vim", "vi"])
def test_merge_files_in_synchronous_editor(
    tmp_path: pathlib.Path, mocker: MockerFixture, editor_cmd: str
) -> None:
    mock_run = mocker.patch(
        "panther_analysis_tool.core.file_editor.subprocess.run", return_value=None
    )

    files = file_editor.MergeableFiles(
        users_file=tmp_path / "users_file.py",
        base_file=tmp_path / "base_file.py",
        panthers_file=tmp_path / "panthers_file.py",
        output_file=tmp_path / "output_file.py",
        premerged_file=tmp_path / "premerged_file.py",
    )
    files.users_file.touch()
    files.base_file.touch()
    files.panthers_file.touch()
    files.output_file.touch()
    files.premerged_file.touch()

    async_edit = file_editor.merge_files_in_editor(files, editor_cmd)
    assert not async_edit
    mock_run.assert_called_once_with([editor_cmd, str(tmp_path / "premerged_file.py")], check=True)


def test_merge_files_default_editor(tmp_path: pathlib.Path, mocker: MockerFixture) -> None:
    mock_run = mocker.patch(
        "panther_analysis_tool.core.file_editor.subprocess.run", return_value=None
    )

    files = file_editor.MergeableFiles(
        users_file=tmp_path / "users_file.py",
        base_file=tmp_path / "base_file.py",
        panthers_file=tmp_path / "panthers_file.py",
        output_file=tmp_path / "output_file.py",
        premerged_file=tmp_path / "premerged_file.py",
    )
    files.users_file.touch()
    files.base_file.touch()
    files.panthers_file.touch()
    files.output_file.touch()
    files.premerged_file.touch()

    async_edit = file_editor.merge_files_in_editor(files, constants.DEFAULT_EDITOR)
    assert not async_edit
    mock_run.assert_called_once_with(
        [constants.DEFAULT_EDITOR, str(tmp_path / "premerged_file.py")], check=True
    )
