import pathlib
from typing import Callable
from unittest.mock import call

import pytest
from pytest_mock import MockerFixture

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.command import merge
from panther_analysis_tool.core import analysis_cache


def _type_to_id_field(analysis_type: str) -> str:
    return {
        "rule": "RuleID",
        "policy": "PolicyID",
        "datamodel": "DataModelID",
    }[analysis_type]


make_load_spec_type = Callable[
    [pathlib.Path, str, str, int, bool], analysis_utils.LoadAnalysisSpecsResult
]


@pytest.fixture
def make_load_spec() -> make_load_spec_type:
    def _make_load_spec(
        tmp_path: pathlib.Path,
        analysis_type: str,
        analysis_id: str,
        base_version: int,
        has_python: bool,
    ) -> analysis_utils.LoadAnalysisSpecsResult:
        python_file = f"{analysis_type}_{analysis_id}.py" if has_python else None
        raw_spec_file_content = f'AnalysisType: {analysis_type}\n{_type_to_id_field(analysis_type)}: "{analysis_id}"\nBaseVersion: {base_version}\n'
        if python_file:
            raw_spec_file_content += f"Filename: {python_file}\n"
            pathlib.Path(tmp_path / python_file).write_text("user_python")

        return analysis_utils.LoadAnalysisSpecsResult(
            spec_filename=str(tmp_path / f"{analysis_type}_{analysis_id}.yml"),
            relative_path=".",
            analysis_spec={
                "AnalysisType": analysis_type,
                _type_to_id_field(analysis_type): analysis_id,
                "BaseVersion": base_version,
                **({"Filename": python_file} if has_python else {}),
            },
            yaml_ctx=analysis_utils.get_yaml_loader(roundtrip=True),
            error=None,
            raw_spec_file_content=raw_spec_file_content.encode("utf-8"),
        )

    return _make_load_spec


make_analysis_spec_type = Callable[[str, str, int, bool], analysis_cache.AnalysisSpec]


@pytest.fixture
def make_analysis_spec() -> make_analysis_spec_type:
    def _make_analysis_spec(
        analysis_type: str, analysis_id: str, version: int, has_python: bool
    ) -> analysis_cache.AnalysisSpec:
        python_file = f"{analysis_type}_{analysis_id}.py" if has_python else None
        raw_spec_file_content = (
            f'AnalysisType: {analysis_type}\n{_type_to_id_field(analysis_type)}: "{analysis_id}"\n'
        )
        if python_file:
            raw_spec_file_content += f"Filename: {python_file}\n"

        return analysis_cache.AnalysisSpec(
            id=123534891243894,
            spec=raw_spec_file_content.encode("utf-8"),
            version=version,
            id_field=_type_to_id_field(analysis_type),
            id_value=analysis_id,
        )

    return _make_analysis_spec


def test_get_mergeable_items_no_analysis_id(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
    make_analysis_spec: make_analysis_spec_type,
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.merge.load_analysis_specs_ex",
        return_value=[
            make_load_spec(tmp_path, "rule", "1", 2, True),  # rule updating from version 2 -> 3
            make_load_spec(tmp_path, "policy", "2", 1, True),  # policy updating from version 1 -> 3
        ],
    )

    get_latest_spec_mock = mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_latest_spec",
        side_effect=[
            make_analysis_spec("rule", "1", 3, True),
            make_analysis_spec("policy", "2", 3, True),
        ],
    )
    get_spec_for_version_mock = mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_spec_for_version",
        side_effect=[
            make_analysis_spec("rule", "1", 2, True),
            make_analysis_spec("policy", "2", 1, True),
        ],
    )
    mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_file_for_spec",
        side_effect=[b"latest_python", b"base_python", b"latest_python", b"base_python"],
    )

    mergeable_items = merge.get_mergeable_items(None)
    assert len(mergeable_items) == 2

    get_latest_spec_mock.assert_has_calls([call("1"), call("2")])
    get_spec_for_version_mock.assert_has_calls([call("1", 2), call("2", 1)])

    # check item 0
    assert mergeable_items[0].user_item == analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "rule",
            "RuleID": "1",
            "BaseVersion": 2,
            "Filename": "rule_1.py",
        },
        raw_yaml_file_contents=b'AnalysisType: rule\nRuleID: "1"\nBaseVersion: 2\nFilename: rule_1.py\n',
        yaml_file_path=str(tmp_path / "rule_1.yml"),
        python_file_contents=b"user_python",
        python_file_path=str(tmp_path / "rule_1.py"),
    )
    assert mergeable_items[0].latest_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "rule",
            "RuleID": "1",
            "Filename": "rule_1.py",
        },
        raw_yaml_file_contents=b'AnalysisType: rule\nRuleID: "1"\nFilename: rule_1.py\n',
        python_file_contents=b"latest_python",
    )
    assert mergeable_items[0].base_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "rule",
            "RuleID": "1",
            "Filename": "rule_1.py",
        },
        raw_yaml_file_contents=b'AnalysisType: rule\nRuleID: "1"\nFilename: rule_1.py\n',
        python_file_contents=b"base_python",
    )

    # check item 1
    assert mergeable_items[1].user_item == analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "policy",
            "PolicyID": "2",
            "BaseVersion": 1,
            "Filename": "policy_2.py",
        },
        raw_yaml_file_contents=b'AnalysisType: policy\nPolicyID: "2"\nBaseVersion: 1\nFilename: policy_2.py\n',
        yaml_file_path=str(tmp_path / "policy_2.yml"),
        python_file_contents=b"user_python",
        python_file_path=str(tmp_path / "policy_2.py"),
    )
    assert mergeable_items[1].latest_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "policy",
            "PolicyID": "2",
            "Filename": "policy_2.py",
        },
        raw_yaml_file_contents=b'AnalysisType: policy\nPolicyID: "2"\nFilename: policy_2.py\n',
        python_file_contents=b"latest_python",
    )
    assert mergeable_items[1].base_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "policy",
            "PolicyID": "2",
            "Filename": "policy_2.py",
        },
        raw_yaml_file_contents=b'AnalysisType: policy\nPolicyID: "2"\nFilename: policy_2.py\n',
        python_file_contents=b"base_python",
    )


def test_get_mergeable_items_no_python(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
    make_analysis_spec: make_analysis_spec_type,
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.merge.load_analysis_specs_ex",
        return_value=[
            make_load_spec(
                tmp_path, "datamodel", "1", 2, False
            ),  # data model that needs updating and has no python
        ],
    )

    get_latest_spec_mock = mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_latest_spec",
        side_effect=[
            make_analysis_spec("datamodel", "1", 3, False),
        ],
    )
    get_spec_for_version_mock = mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_spec_for_version",
        side_effect=[
            make_analysis_spec("datamodel", "1", 2, False),
        ],
    )
    mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_file_for_spec",
        side_effect=[None, None],
    )

    mergeable_items = merge.get_mergeable_items(None)
    assert len(mergeable_items) == 1

    get_latest_spec_mock.assert_has_calls([call("1")])
    get_spec_for_version_mock.assert_has_calls([call("1", 2)])

    # check item 0
    assert mergeable_items[0].user_item == analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "datamodel",
            "DataModelID": "1",
            "BaseVersion": 2,
        },
        raw_yaml_file_contents=b'AnalysisType: datamodel\nDataModelID: "1"\nBaseVersion: 2\n',
        yaml_file_path=str(tmp_path / "datamodel_1.yml"),
    )
    assert mergeable_items[0].latest_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "datamodel",
            "DataModelID": "1",
        },
        raw_yaml_file_contents=b'AnalysisType: datamodel\nDataModelID: "1"\n',
    )
    assert mergeable_items[0].base_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents={
            "AnalysisType": "datamodel",
            "DataModelID": "1",
        },
        raw_yaml_file_contents=b'AnalysisType: datamodel\nDataModelID: "1"\n',
    )


def test_get_mergeable_items_no_update_needed(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
    make_analysis_spec: make_analysis_spec_type,
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.merge.load_analysis_specs_ex",
        return_value=[
            make_load_spec(tmp_path, "rule", "1", 2, True),  # rule that does not need updating
        ],
    )
    get_latest_spec_mock = mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_latest_spec",
        side_effect=[
            make_analysis_spec("rule", "1", 2, True),
        ],
    )

    mergeable_items = merge.get_mergeable_items(None)
    assert len(mergeable_items) == 0

    get_latest_spec_mock.assert_has_calls([call("1")])


def test_get_mergeable_items_base_version_too_high(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
    make_analysis_spec: make_analysis_spec_type,
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.merge.load_analysis_specs_ex",
        return_value=[
            make_load_spec(tmp_path, "rule", "1", 3, True),  # rule that has a base version too high
        ],
    )
    get_latest_spec_mock = mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_latest_spec",
        side_effect=[
            make_analysis_spec("rule", "1", 2, True),
        ],
    )
    logging_mock = mocker.patch("panther_analysis_tool.command.merge.logging.warning")

    mergeable_items = merge.get_mergeable_items(None)
    assert len(mergeable_items) == 0

    get_latest_spec_mock.assert_has_calls([call("1")])
    logging_mock.assert_has_calls(
        [call("User spec %s has a base version greater than the latest version %s, skipping", "1", 2)]
    )

    # rule that has a base version not in cache
    # custom rule no in cache
    # with analysis id


# def test_merge_items_no_conflict(mocker: MockerFixture, yaml_mergable_item: merge.MergeableItem) -> None:
#     mocker.patch("merge.git_helpers.merge_file", return_value=(False, b"merged_yaml"))
#     mocker.patch("merge.editor.merge_files_in_editor", return_value=None)
#     merge.merge_items([mergeable_items], analysis_id)


def test_merge_file_yaml_no_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user_yaml")
    mocker.patch(
        "panther_analysis_tool.command.merge.git_helpers.merge_file",
        return_value=(False, b"merged_yaml"),
    )

    has_conflict = merge.merge_file(
        solve_merge=False,
        user_item_id="1",
        user=b"user_yaml",
        base=b"base_yaml",
        latest=b"base_yaml",
        output_path=str(output_path),
    )
    assert not has_conflict
    assert output_path.read_text() == "merged_yaml"


def test_merge_file_yaml_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user_yaml")
    mocker.patch(
        "panther_analysis_tool.command.merge.git_helpers.merge_file",
        return_value=(True, b"merged_yaml"),
    )

    has_conflict = merge.merge_file(
        solve_merge=False,
        user_item_id="1",
        user=b"user_yaml",
        base=b"base_yaml",
        latest=b"base_yaml",
        output_path=str(output_path),
    )
    assert has_conflict
    assert output_path.read_text() == "user_yaml"


def test_merge_file_yaml_conflict_solve(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user_yaml")
    mocker.patch(
        "panther_analysis_tool.command.merge.git_helpers.merge_file",
        return_value=(True, b"merged_yaml"),
    )

    has_conflict = merge.merge_file(
        solve_merge=True,
        user_item_id="1",
        user=b"user_yaml",
        base=b"base_yaml",
        latest=b"base_yaml",
        output_path=str(output_path),
    )
    assert not has_conflict
    assert output_path.read_text() == "user_yaml"


def test_merge_file_python_no_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.py"
    output_path.write_text("user_python")
    mocker.patch(
        "panther_analysis_tool.command.merge.git_helpers.merge_file",
        return_value=(False, b"merged_python"),
    )

    has_conflict = merge.merge_file(
        solve_merge=False,
        user_item_id="1",
        user=b"user_python",
        base=b"base_python",
        latest=b"base_python",
        output_path=str(output_path),
    )
    assert not has_conflict
    assert output_path.read_text() == "merged_python"


def test_merge_file_python_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.py"
    output_path.write_text("user_python")
    mocker.patch(
        "panther_analysis_tool.command.merge.git_helpers.merge_file",
        return_value=(True, b"merged_python"),
    )

    has_conflict = merge.merge_file(
        solve_merge=False,
        user_item_id="1",
        user=b"user_python",
        base=b"base_python",
        latest=b"base_python",
        output_path=str(output_path),
    )
    assert has_conflict
    assert output_path.read_text() == "user_python"


def test_merge_file_python_conflict_solve(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.py"
    output_path.write_text("user_python")
    mocker.patch(
        "panther_analysis_tool.command.merge.git_helpers.merge_file",
        return_value=(True, b"merged_python"),
    )
    merge_files_mock = mocker.patch(
        "panther_analysis_tool.command.merge.editor.merge_files_in_editor", return_value=None
    )
    merge_files_mock.side_effect = lambda _: output_path.write_text("merged_python")

    has_conflict = merge.merge_file(
        solve_merge=True,
        user_item_id="1",
        user=b"user_python",
        base=b"base_python",
        latest=b"base_python",
        output_path=str(output_path),
    )
    assert not has_conflict
    assert output_path.read_text() == "merged_python"
    assert output_path.read_text() == "merged_python"
