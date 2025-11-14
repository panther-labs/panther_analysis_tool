import pathlib
from typing import Any, Callable, Protocol
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


class MakeAnalysisItemType(Protocol):
    def __call__(
        self,
        yaml_file_contents: dict[str, Any],
        raw_yaml_file_contents: bytes | None = None,
        yaml_file_path: str | None = None,
        python_file_contents: bytes | None = None,
        python_file_path: str | None = None,
    ) -> analysis_utils.AnalysisItem: ...


@pytest.fixture
def make_analysis_item() -> MakeAnalysisItemType:
    def _make_analysis_item(
        yaml_file_contents: dict[str, Any],
        raw_yaml_file_contents: bytes | None = None,
        yaml_file_path: str | None = None,
        python_file_contents: bytes | None = None,
        python_file_path: str | None = None,
    ) -> analysis_utils.AnalysisItem:
        return analysis_utils.AnalysisItem(
            yaml_file_contents=yaml_file_contents,
            raw_yaml_file_contents=raw_yaml_file_contents,
            yaml_file_path=yaml_file_path,
            python_file_contents=python_file_contents,
            python_file_path=python_file_path,
        )

    return _make_analysis_item


def load_spec_to_analysis_item(
    spec: analysis_utils.LoadAnalysisSpecsResult, py: bytes | None
) -> analysis_utils.AnalysisItem:
    return analysis_utils.AnalysisItem(
        yaml_file_contents=spec.analysis_spec,
        raw_yaml_file_contents=spec.raw_spec_file_content,
        yaml_file_path=spec.spec_filename,
        python_file_contents=py,
        python_file_path=(
            str(pathlib.Path(spec.spec_filename).parent / spec.analysis_spec.get("Filename"))
            if "Filename" in spec.analysis_spec
            else None
        ),
    )


################################################################################
### TEST get_mergeable_items
################################################################################


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
    mock_sqlite = tmp_path / ".cache" / "panther-analysis.sqlite"
    mock_sqlite.parent.mkdir(parents=True, exist_ok=True)
    mock_sqlite.touch()
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.PANTHER_ANALYSIS_SQLITE_FILE_PATH",
        mock_sqlite,
    )

    mergeable_items = merge.get_mergeable_items(None)
    assert len(mergeable_items) == 2

    get_latest_spec_mock.assert_has_calls([call("1"), call("2")])
    get_spec_for_version_mock.assert_has_calls([call("1", 2), call("2", 1)])

    # check item 0
    yaml_file_contents = {
        "AnalysisType": "rule",
        "RuleID": "1",
        "Filename": "rule_1.py",
    }
    assert mergeable_items[0].user_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents | {"BaseVersion": 2},
        raw_yaml_file_contents=b'AnalysisType: rule\nRuleID: "1"\nBaseVersion: 2\nFilename: rule_1.py\n',
        yaml_file_path=str(tmp_path / "rule_1.yml"),
        python_file_contents=b"user_python",
        python_file_path=str(tmp_path / "rule_1.py"),
    )
    assert mergeable_items[0].latest_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents,
        raw_yaml_file_contents=b'AnalysisType: rule\nRuleID: "1"\nFilename: rule_1.py\n',
        python_file_contents=b"latest_python",
    )
    assert mergeable_items[0].base_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents,
        raw_yaml_file_contents=b'AnalysisType: rule\nRuleID: "1"\nFilename: rule_1.py\n',
        python_file_contents=b"base_python",
    )

    # check item 1
    yaml_file_contents = {
        "AnalysisType": "policy",
        "PolicyID": "2",
        "Filename": "policy_2.py",
    }
    assert mergeable_items[1].user_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents | {"BaseVersion": 1},
        raw_yaml_file_contents=b'AnalysisType: policy\nPolicyID: "2"\nBaseVersion: 1\nFilename: policy_2.py\n',
        yaml_file_path=str(tmp_path / "policy_2.yml"),
        python_file_contents=b"user_python",
        python_file_path=str(tmp_path / "policy_2.py"),
    )
    assert mergeable_items[1].latest_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents,
        raw_yaml_file_contents=b'AnalysisType: policy\nPolicyID: "2"\nFilename: policy_2.py\n',
        python_file_contents=b"latest_python",
    )
    assert mergeable_items[1].base_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents,
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
    mock_sqlite = tmp_path / ".cache" / "panther-analysis.sqlite"
    mock_sqlite.parent.mkdir(parents=True, exist_ok=True)
    mock_sqlite.touch()
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.PANTHER_ANALYSIS_SQLITE_FILE_PATH",
        mock_sqlite,
    )

    mergeable_items = merge.get_mergeable_items(None)
    assert len(mergeable_items) == 1

    get_latest_spec_mock.assert_has_calls([call("1")])
    get_spec_for_version_mock.assert_has_calls([call("1", 2)])

    # check item 0
    yaml_file_contents = {
        "AnalysisType": "datamodel",
        "DataModelID": "1",
    }
    assert mergeable_items[0].user_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents | {"BaseVersion": 2},
        raw_yaml_file_contents=b'AnalysisType: datamodel\nDataModelID: "1"\nBaseVersion: 2\n',
        yaml_file_path=str(tmp_path / "datamodel_1.yml"),
    )
    assert mergeable_items[0].latest_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents,
        raw_yaml_file_contents=b'AnalysisType: datamodel\nDataModelID: "1"\n',
    )
    assert mergeable_items[0].base_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents,
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
    mock_sqlite = tmp_path / ".cache" / "panther-analysis.sqlite"
    mock_sqlite.parent.mkdir(parents=True, exist_ok=True)
    mock_sqlite.touch()
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.PANTHER_ANALYSIS_SQLITE_FILE_PATH",
        mock_sqlite,
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
    mock_sqlite = tmp_path / ".cache" / "panther-analysis.sqlite"
    mock_sqlite.parent.mkdir(parents=True, exist_ok=True)
    mock_sqlite.touch()
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.PANTHER_ANALYSIS_SQLITE_FILE_PATH",
        mock_sqlite,
    )

    mergeable_items = merge.get_mergeable_items(None)
    assert len(mergeable_items) == 0

    get_latest_spec_mock.assert_has_calls([call("1")])
    logging_mock.assert_has_calls(
        [
            call(
                "User spec %s has a base version greater than the latest version %s, skipping",
                "1",
                2,
            )
        ]
    )


def test_get_mergeable_items_custom_rule(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.merge.load_analysis_specs_ex",
        return_value=[
            make_load_spec(tmp_path, "rule", "custom", 2, True),
        ],
    )
    get_latest_spec_mock = mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_latest_spec",
        side_effect=[None],
    )
    mock_sqlite = tmp_path / ".cache" / "panther-analysis.sqlite"
    mock_sqlite.parent.mkdir(parents=True, exist_ok=True)
    mock_sqlite.touch()
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.PANTHER_ANALYSIS_SQLITE_FILE_PATH",
        mock_sqlite,
    )

    mergeable_items = merge.get_mergeable_items(None)
    assert len(mergeable_items) == 0

    get_latest_spec_mock.assert_has_calls([call("custom")])


def test_get_mergeable_items_base_version_added(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
    make_analysis_spec: make_analysis_spec_type,
) -> None:
    mock_load_spec = make_load_spec(tmp_path, "rule", "1", 1, True)
    del mock_load_spec.analysis_spec["BaseVersion"]
    mocker.patch(
        "panther_analysis_tool.command.merge.load_analysis_specs_ex",
        return_value=[mock_load_spec],
    )
    get_latest_spec_mock = mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_latest_spec",
        side_effect=[make_analysis_spec("rule", "1", 2, True)],
    )
    mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_spec_for_version",
        side_effect=[
            make_analysis_spec("rule", "1", 1, True),
        ],
    )
    mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_file_for_spec",
        side_effect=[b"latest_python", b"base_python"],
    )
    mock_sqlite = tmp_path / ".cache" / "panther-analysis.sqlite"
    mock_sqlite.parent.mkdir(parents=True, exist_ok=True)
    mock_sqlite.touch()
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.PANTHER_ANALYSIS_SQLITE_FILE_PATH",
        mock_sqlite,
    )
    mergeable_items = merge.get_mergeable_items(None)
    assert len(mergeable_items) == 1
    assert mergeable_items[0].user_item.yaml_file_contents["BaseVersion"] == 1
    get_latest_spec_mock.assert_has_calls([call("1")])


def test_get_mergeable_items_with_analysis_id(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
    make_analysis_spec: make_analysis_spec_type,
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.merge.load_analysis_specs_ex",
        return_value=[
            make_load_spec(tmp_path, "rule", "1", 2, True),
            make_load_spec(tmp_path, "rule", "target", 2, True),
        ],
    )
    get_latest_spec_mock = mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_latest_spec",
        side_effect=[make_analysis_spec("rule", "target", 3, True), None],
    )
    get_spec_for_version_mock = mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_spec_for_version",
        side_effect=[
            make_analysis_spec("rule", "target", 2, True),
        ],
    )
    mocker.patch(
        "panther_analysis_tool.command.merge.analysis_cache.AnalysisCache.get_file_for_spec",
        side_effect=[b"latest_python", b"base_python"],
    )
    mock_sqlite = tmp_path / ".cache" / "panther-analysis.sqlite"
    mock_sqlite.parent.mkdir(parents=True, exist_ok=True)
    mock_sqlite.touch()
    mocker.patch(
        "panther_analysis_tool.core.analysis_cache.PANTHER_ANALYSIS_SQLITE_FILE_PATH",
        mock_sqlite,
    )

    mergeable_items = merge.get_mergeable_items("target")
    assert len(mergeable_items) == 1

    get_latest_spec_mock.assert_has_calls([call("target")])
    get_spec_for_version_mock.assert_has_calls([call("target", 2)])

    # check item 0
    yaml_file_contents = {
        "AnalysisType": "rule",
        "RuleID": "target",
        "Filename": "rule_target.py",
    }
    assert mergeable_items[0].user_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents | {"BaseVersion": 2},
        raw_yaml_file_contents=b'AnalysisType: rule\nRuleID: "target"\nBaseVersion: 2\nFilename: rule_target.py\n',
        yaml_file_path=str(tmp_path / "rule_target.yml"),
        python_file_contents=b"user_python",
        python_file_path=str(tmp_path / "rule_target.py"),
    )
    assert mergeable_items[0].latest_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents,
        raw_yaml_file_contents=b'AnalysisType: rule\nRuleID: "target"\nFilename: rule_target.py\n',
        python_file_contents=b"latest_python",
    )
    assert mergeable_items[0].base_panther_item == analysis_utils.AnalysisItem(
        yaml_file_contents=yaml_file_contents,
        raw_yaml_file_contents=b'AnalysisType: rule\nRuleID: "target"\nFilename: rule_target.py\n',
        python_file_contents=b"base_python",
    )


################################################################################
### TEST merge_items
################################################################################


def test_merge_items_no_conflict_with_python(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.merge.merge_file",
        side_effect=[False, False, False, False],
    )
    mock_print = mocker.patch("panther_analysis_tool.command.merge.print")

    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, True)
    rule_2 = make_load_spec(tmp_path, "rule", "2", 1, True)

    mergeable_items = [
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
        ),
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_2, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_2, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_2, b"base_python"),
        ),
    ]
    merge.merge_items(mergeable_items, None, None)
    mock_print.assert_has_calls(
        [
            call("Updated 2 analysis item(s) with latest Panther version:"),
            call("  * 1"),
            call("  * 2"),
            call(
                "Run `git diff` to see the changes. Run `pat test` to test the changes and `pat upload` to upload them."
            ),
        ]
    )


def test_merge_items_no_conflict_no_python(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.merge.merge_file",
        side_effect=[False, False],
    )
    mock_print = mocker.patch("panther_analysis_tool.command.merge.print")

    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, False)
    rule_2 = make_load_spec(tmp_path, "rule", "2", 1, False)

    mergeable_items = [
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, None),
            latest_panther_item=load_spec_to_analysis_item(rule_1, None),
            base_panther_item=load_spec_to_analysis_item(rule_1, None),
        ),
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_2, None),
            latest_panther_item=load_spec_to_analysis_item(rule_2, None),
            base_panther_item=load_spec_to_analysis_item(rule_2, None),
        ),
    ]
    merge.merge_items(mergeable_items, None, None)
    mock_print.assert_has_calls(
        [
            call("Updated 2 analysis item(s) with latest Panther version:"),
            call("  * 1"),
            call("  * 2"),
            call(
                "Run `git diff` to see the changes. Run `pat test` to test the changes and `pat upload` to upload them."
            ),
        ]
    )


def test_merge_items_yaml_conflict(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.merge.merge_file",
        side_effect=[True, True],
    )
    mock_print = mocker.patch("panther_analysis_tool.command.merge.print")

    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, False)
    rule_2 = make_load_spec(tmp_path, "rule", "2", 1, False)

    mergeable_items = [
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, None),
            latest_panther_item=load_spec_to_analysis_item(rule_1, None),
            base_panther_item=load_spec_to_analysis_item(rule_1, None),
        ),
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_2, None),
            latest_panther_item=load_spec_to_analysis_item(rule_2, None),
            base_panther_item=load_spec_to_analysis_item(rule_2, None),
        ),
    ]
    merge.merge_items(mergeable_items, None, None)
    mock_print.assert_has_calls(
        [
            call(
                "2 merge conflict(s) found, run `EDITOR=<editor> pat merge <id>` to resolve each conflict:"
            ),
            call("  * 1"),
            call("  * 2"),
        ]
    )


def test_merge_items_python_conflict(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mock_merge_file = mocker.patch(
        "panther_analysis_tool.command.merge.merge_file",
        side_effect=[False, False, True],
    )
    mock_print = mocker.patch("panther_analysis_tool.command.merge.print")

    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, True)
    rule_2 = make_load_spec(tmp_path, "rule", "2", 1, True)

    mergeable_items = [
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
        ),
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_2, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_2, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_2, b"base_python"),
        ),
    ]
    merge.merge_items(mergeable_items, None, None)
    mock_print.assert_has_calls(
        [
            call("Updated 1 analysis item(s) with latest Panther version:"),
            call("  * 1"),
            call(
                "1 merge conflict(s) found, run `EDITOR=<editor> pat merge <id>` to resolve each conflict:"
            ),
            call("  * 2"),
            call(
                "Run `git diff` to see the changes. Run `pat test` to test the changes and `pat upload` to upload them."
            ),
        ]
    )
    assert mock_merge_file.call_count == 3


def test_merge_items_both_conflicts(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mock_merge_file = mocker.patch(
        "panther_analysis_tool.command.merge.merge_file",
        side_effect=[
            False,  # no python conflict
            True,  # yaml conflict
            True,  # python conflict
        ],
    )
    mock_print = mocker.patch("panther_analysis_tool.command.merge.print")

    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, True)
    rule_2 = make_load_spec(tmp_path, "rule", "2", 1, True)

    mergeable_items = [
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
        ),
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_2, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_2, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_2, b"base_python"),
        ),
    ]
    merge.merge_items(mergeable_items, None, None)
    mock_print.assert_has_calls(
        [
            call(
                "2 merge conflict(s) found, run `EDITOR=<editor> pat merge <id>` to resolve each conflict:"
            ),
            call("  * 1"),
            call("  * 2"),
        ]
    )
    assert mock_merge_file.call_count == 3


def test_merge_items_with_analysis_id_with_conflict(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mock_merge_file = mocker.patch(
        "panther_analysis_tool.command.merge.merge_file",
        side_effect=[True, False],
    )
    mock_print = mocker.patch("panther_analysis_tool.command.merge.print")

    rule_1 = make_load_spec(tmp_path, "rule", "target", 1, True)

    mergeable_items = [
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
        ),
    ]
    merge.merge_items(mergeable_items, "target", None)
    mock_print.assert_has_calls([])
    assert mock_merge_file.call_count == 2


def test_merge_items_with_analysis_id_no_conflict(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mock_merge_file = mocker.patch(
        "panther_analysis_tool.command.merge.merge_file",
        side_effect=[False, False],
    )
    mock_print = mocker.patch("panther_analysis_tool.command.merge.print")

    rule_1 = make_load_spec(tmp_path, "rule", "target", 1, True)

    mergeable_items = [
        merge.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
        ),
    ]
    merge.merge_items(mergeable_items, "target", None)
    mock_print.assert_has_calls([])
    assert mock_merge_file.call_count == 2


################################################################################
### TEST merge_file
################################################################################


def test_merge_file_yaml_no_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user: yaml")
    mocker.patch(
        "panther_analysis_tool.command.merge.git_helpers.merge_file",
        return_value=(False, b"merged: yaml"),
    )

    has_conflict = merge.merge_file(
        solve_merge=False,
        user=b"user: yaml",
        base=b"base: yaml",
        latest=b"base: yaml",
        user_python=b"",
        output_path=output_path,
        editor=None,
    )
    assert not has_conflict
    assert output_path.read_text() == "user: yaml\nbase: yaml\n"


def test_merge_file_yaml_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user: yaml")
    mocker.patch(
        "panther_analysis_tool.command.merge.git_helpers.merge_file",
        return_value=(True, b"merged: yaml"),
    )

    has_conflict = merge.merge_file(
        solve_merge=False,
        user=b"key: user",
        base=b"key: base",
        latest=b"key: latest",
        user_python=b"",
        output_path=output_path,
        editor=None,
    )
    assert has_conflict
    # output file should not have changed
    assert output_path.read_text() == "user: yaml"


def test_merge_file_yaml_conflict_solve(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("common: user")
    mocker.patch(
        "panther_analysis_tool.command.merge.git_helpers.merge_file",
        return_value=(True, b"merged: yaml"),
    )
    mocker.patch(
        "panther_analysis_tool.command.merge.yaml_conflict_resolver_gui.YAMLConflictResolverApp",
        return_value=mocker.Mock(get_final_dict=lambda: {"common": "user"}, run=lambda: None),
    )

    has_conflict = merge.merge_file(
        solve_merge=True,
        user=b"common: user",
        base=b"common: base",
        latest=b"common: latest",
        user_python=b"",
        output_path=output_path,
        editor=None,
    )
    assert not has_conflict
    assert output_path.read_text() == "common: user\n"


def test_merge_file_python_no_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.py"
    output_path.write_text("user_python")
    mocker.patch(
        "panther_analysis_tool.command.merge.git_helpers.merge_file",
        return_value=(False, b"merged_python"),
    )

    has_conflict = merge.merge_file(
        solve_merge=False,
        user=b"user_python",
        base=b"base_python",
        latest=b"base_python",
        user_python=b"user_python",
        output_path=output_path,
        editor=None,
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
        user=b"user_python",
        base=b"base_python",
        latest=b"base_python",
        user_python=b"user_python",
        output_path=output_path,
        editor=None,
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
        "panther_analysis_tool.command.merge.file_editor.merge_files_in_editor", return_value=False
    )
    merge_files_mock.side_effect = lambda _, **kwargs: output_path.write_text("merged_python")

    has_conflict = merge.merge_file(
        solve_merge=True,
        user=b"user_python",
        base=b"base_python",
        latest=b"base_python",
        user_python=b"user_python",
        output_path=output_path,
        editor=None,
    )
    assert not has_conflict
    assert output_path.read_text() == "merged_python"
    assert output_path.read_text() == "merged_python"
