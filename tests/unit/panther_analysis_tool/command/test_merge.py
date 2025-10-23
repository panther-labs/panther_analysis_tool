import pathlib

import pytest
from pytest_mock import MockerFixture

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.command import merge


@pytest.fixture
def yaml_mergable_item() -> merge.MergeableItem:
    return merge.MergeableItem(
        user_item=analysis_utils.AnalysisItem(
            yaml_file_contents={"key": "value"},
            raw_yaml_file_contents=b"user_yaml",
        ),
        latest_panther_item=analysis_utils.AnalysisItem(
            yaml_file_contents={"key": "value"},
            raw_yaml_file_contents=b"latest_yaml",
        ),
        base_panther_item=analysis_utils.AnalysisItem(
            yaml_file_contents={"key": "value"},
            raw_yaml_file_contents=b"base_yaml",
        ),
    )

# def test_merge_items_no_conflict(mocker: MockerFixture, yaml_mergable_item: merge.MergeableItem) -> None:
#     mocker.patch("merge.git_helpers.merge_file", return_value=(False, b"merged_yaml"))
#     mocker.patch("merge.editor.merge_files_in_editor", return_value=None)
#     merge.merge_items([mergeable_items], analysis_id)

def test_merge_file_yaml_no_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user_yaml")
    mocker.patch("panther_analysis_tool.command.merge.git_helpers.merge_file", return_value=(False, b"merged_yaml"))
    
    has_conflict = merge.merge_file(solve_merge=False, user_item_id="1", user=b"user_yaml", base=b"base_yaml", latest=b"base_yaml", output_path=str(output_path))
    assert not has_conflict
    assert output_path.read_text() == "merged_yaml"


def test_merge_file_yaml_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user_yaml")
    mocker.patch("panther_analysis_tool.command.merge.git_helpers.merge_file", return_value=(True, b"merged_yaml"))
    
    has_conflict = merge.merge_file(solve_merge=False, user_item_id="1", user=b"user_yaml", base=b"base_yaml", latest=b"base_yaml", output_path=str(output_path))
    assert has_conflict
    assert output_path.read_text() == "user_yaml"

def test_merge_file_yaml_conflict_solve(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user_yaml")
    mocker.patch("panther_analysis_tool.command.merge.git_helpers.merge_file", return_value=(True, b"merged_yaml"))
    
    has_conflict = merge.merge_file(solve_merge=True, user_item_id="1", user=b"user_yaml", base=b"base_yaml", latest=b"base_yaml", output_path=str(output_path))
    assert not has_conflict
    assert output_path.read_text() == "user_yaml"


def test_merge_file_python_no_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.py"
    output_path.write_text("user_python")
    mocker.patch("panther_analysis_tool.command.merge.git_helpers.merge_file", return_value=(False, b"merged_python"))
    
    has_conflict = merge.merge_file(solve_merge=False, user_item_id="1", user=b"user_python", base=b"base_python", latest=b"base_python", output_path=str(output_path))
    assert not has_conflict
    assert output_path.read_text() == "merged_python"

def test_merge_file_python_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.py"
    output_path.write_text("user_python")
    mocker.patch("panther_analysis_tool.command.merge.git_helpers.merge_file", return_value=(True, b"merged_python"))
    
    has_conflict = merge.merge_file(solve_merge=False, user_item_id="1", user=b"user_python", base=b"base_python", latest=b"base_python", output_path=str(output_path))
    assert has_conflict
    assert output_path.read_text() == "user_python"

def test_merge_file_python_conflict_solve(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.py"
    output_path.write_text("user_python")
    mocker.patch("panther_analysis_tool.command.merge.git_helpers.merge_file", return_value=(True, b"merged_python"))
    merge_files_mock = mocker.patch("panther_analysis_tool.command.merge.editor.merge_files_in_editor", return_value=None)
    merge_files_mock.side_effect = lambda _: output_path.write_text("merged_python")

    has_conflict = merge.merge_file(solve_merge=True, user_item_id="1", user=b"user_python", base=b"base_python", latest=b"base_python", output_path=str(output_path))
    assert not has_conflict
    assert output_path.read_text() == "merged_python"
    