import pathlib
from typing import Any, Callable, Protocol

import pytest
from pytest_mock import MockerFixture

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.constants import AutoAcceptOption
from panther_analysis_tool.core import analysis_cache, merge_item, yaml


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
            yaml_ctx=yaml.BlockStyleYAML(),
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
### TEST merge_items
################################################################################


def test_merge_item_no_conflict_with_python(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mock_merge_file = mocker.patch(
        "panther_analysis_tool.core.merge_item.merge_file",
        side_effect=[(False, b"merged"), (False, b"merged")],
    )

    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, True)
    pathlib.Path(rule_1.spec_filename).write_text("user: yaml")

    has_conflict = merge_item.merge_item(
        merge_item.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
        ),
        False,
        None,
    )
    assert not has_conflict
    assert mock_merge_file.call_count == 2
    assert pathlib.Path(rule_1.spec_filename).read_text() == "merged"
    assert pathlib.Path(rule_1.python_file_path() or "").read_text() == "merged"


def test_merge_items_no_conflict_no_python(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mock_merge_file = mocker.patch(
        "panther_analysis_tool.core.merge_item.merge_file",
        side_effect=[(False, b"merged")],
    )

    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, False)
    pathlib.Path(rule_1.spec_filename).write_text("user: yaml")

    has_conflict = merge_item.merge_item(
        merge_item.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, None),
            latest_panther_item=load_spec_to_analysis_item(rule_1, None),
            base_panther_item=load_spec_to_analysis_item(rule_1, None),
        ),
        False,
        None,
    )
    assert not has_conflict
    assert mock_merge_file.call_count == 1
    assert pathlib.Path(rule_1.spec_filename).read_text() == "merged"


def test_merge_items_yaml_conflict(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mock_merge_file = mocker.patch(
        "panther_analysis_tool.core.merge_item.merge_file",
        side_effect=[(True, b"")],
    )

    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, False)

    has_conflict = merge_item.merge_item(
        merge_item.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, None),
            latest_panther_item=load_spec_to_analysis_item(rule_1, None),
            base_panther_item=load_spec_to_analysis_item(rule_1, None),
        ),
        False,
        None,
    )
    assert has_conflict
    assert mock_merge_file.call_count == 1


def test_merge_item_python_conflict(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mock_merge_file = mocker.patch(
        "panther_analysis_tool.core.merge_item.merge_file",
        side_effect=[(False, b"merged"), (True, b"")],
    )

    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, True)

    has_conflict = merge_item.merge_item(
        merge_item.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
        ),
        False,
        None,
    )
    assert has_conflict
    assert mock_merge_file.call_count == 2


def test_merge_item_with_analysis_id_with_conflict(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mock_merge_file = mocker.patch(
        "panther_analysis_tool.core.merge_item.merge_file",
        side_effect=[(True, b""), (False, b"merged")],
    )

    rule_1 = make_load_spec(tmp_path, "rule", "target", 1, True)
    pathlib.Path(rule_1.spec_filename).write_text("user: yaml")

    merge_item.merge_item(
        merge_item.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
        ),
        True,
        None,
    )
    assert mock_merge_file.call_count == 2
    assert pathlib.Path(rule_1.spec_filename).read_text() == "user: yaml"


def test_merge_item_with_analysis_id_no_conflict(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    mock_merge_file = mocker.patch(
        "panther_analysis_tool.core.merge_item.merge_file",
        side_effect=[(False, b"merged"), (False, b"merged")],
    )

    rule_1 = make_load_spec(tmp_path, "rule", "target", 1, True)
    pathlib.Path(rule_1.spec_filename).write_text("user: yaml")

    merge_item.merge_item(
        merge_item.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
        ),
        True,
        None,
    )
    assert mock_merge_file.call_count == 2
    assert pathlib.Path(rule_1.spec_filename).read_text() == "merged"


def test_merge_item_write_merge_conflicts_and_auto_accept(
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, False)
    with pytest.raises(RuntimeError):
        merge_item.merge_item(
            merge_item.MergeableItem(
                user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
                latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
                base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
            ),
            solve_merge=True,
            editor=None,
            auto_accept=AutoAcceptOption.YOURS,
            write_merge_conflicts=True,
        )


def test_merge_item_write_merge_conflicts(
    monkeypatch: pytest.MonkeyPatch,
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    monkeypatch.chdir(tmp_path)

    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, True)
    yaml_file_path = pathlib.Path(rule_1.spec_filename)
    python_file_path = pathlib.Path(rule_1.python_file_path() or "")

    # Mock diff.Dict.merge_dict to return conflicts so git_helpers.merge_file is called for YAML
    mocker.patch(
        "panther_analysis_tool.core.merge_item.diff.Dict.merge_dict",
        return_value=[{"key": "Description"}],  # Return a list of conflicts
    )

    # Mock git_helpers.merge_file to return conflict markers
    conflict_yaml = b"<<<<<<< yours\nuser: yaml\n=======\nlatest: yaml\n>>>>>>> panthers\n"
    conflict_python = b"<<<<<<< yours\nuser_python\n=======\nlatest_python\n>>>>>>> panthers\n"

    mock_merge_file = mocker.patch(
        "panther_analysis_tool.core.merge_item.git_helpers.merge_file",
        side_effect=[
            (True, conflict_yaml),  # YAML conflict
            (True, conflict_python),  # Python conflict
        ],
    )

    has_conflicts = merge_item.merge_item(
        merge_item.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
        ),
        solve_merge=False,
        editor=None,
        write_merge_conflicts=True,
    )

    assert has_conflicts
    # Verify git_helpers.merge_file was called for both YAML and Python
    assert mock_merge_file.call_count == 2
    # Verify conflict markers were written to YAML file
    assert yaml_file_path.read_bytes() == conflict_yaml
    # Verify conflict markers were written to Python file
    assert python_file_path.read_bytes() == conflict_python


def test_merge_item_write_merge_conflicts_and_solve_merge(
    monkeypatch: pytest.MonkeyPatch,
    mocker: MockerFixture,
    tmp_path: pathlib.Path,
    make_load_spec: make_load_spec_type,
) -> None:
    monkeypatch.chdir(tmp_path)

    rule_1 = make_load_spec(tmp_path, "rule", "1", 1, True)
    yaml_file_path = pathlib.Path(rule_1.spec_filename)
    python_file_path = pathlib.Path(rule_1.python_file_path() or "")

    # Mock diff.Dict.merge_dict to return conflicts so git_helpers.merge_file is called for YAML
    mocker.patch(
        "panther_analysis_tool.core.merge_item.diff.Dict.merge_dict",
        return_value=[{"key": "Description"}],  # Return a list of conflicts
    )

    # Mock git_helpers.merge_file to return conflict markers
    conflict_yaml = b"<<<<<<< yours\nuser: yaml\n=======\nlatest: yaml\n>>>>>>> panthers\n"
    conflict_python = b"<<<<<<< yours\nuser_python\n=======\nlatest_python\n>>>>>>> panthers\n"

    mock_merge_file = mocker.patch(
        "panther_analysis_tool.core.merge_item.git_helpers.merge_file",
        side_effect=[
            (True, conflict_yaml),  # YAML conflict
            (True, conflict_python),  # Python conflict
        ],
    )

    has_conflicts = merge_item.merge_item(
        merge_item.MergeableItem(
            user_item=load_spec_to_analysis_item(rule_1, b"user_python"),
            latest_panther_item=load_spec_to_analysis_item(rule_1, b"latest_python"),
            base_panther_item=load_spec_to_analysis_item(rule_1, b"base_python"),
        ),
        solve_merge=True,  # true when an analysis id is provided
        editor=None,
        write_merge_conflicts=True,
    )

    assert has_conflicts
    # Verify git_helpers.merge_file was called for both YAML and Python
    assert mock_merge_file.call_count == 2
    # Verify conflict markers were written to YAML file
    assert yaml_file_path.read_bytes() == conflict_yaml
    # Verify conflict markers were written to Python file
    assert python_file_path.read_bytes() == conflict_python


################################################################################
### TEST merge_file
################################################################################


def test_merge_file_yaml_no_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user: yaml")

    has_conflict, merged_contents = merge_item.merge_file(
        solve_merge=False,
        user=b"user: yaml",
        base=b"base: yaml",
        latest=b"base: yaml",
        user_python=b"",
        output_path=output_path,
        editor=None,
    )
    assert not has_conflict
    assert merged_contents == b"user: yaml\nbase: yaml\n"
    assert output_path.read_text() == "user: yaml"


def test_merge_file_yaml_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user: yaml")
    mocker.patch(
        "panther_analysis_tool.core.merge_item.git_helpers.merge_file",
        return_value=(True, b"merged: yaml"),
    )

    has_conflict = merge_item.merge_file(
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
        "panther_analysis_tool.core.merge_item.yaml_conflict_resolver_gui.YAMLConflictResolverApp",
        return_value=mocker.Mock(get_final_dict=lambda: {"common": "user"}, run=lambda: None),
    )

    has_conflict, merged_contents = merge_item.merge_file(
        solve_merge=True,
        user=b"common: user",
        base=b"common: base",
        latest=b"common: latest",
        user_python=b"",
        output_path=output_path,
        editor=None,
    )
    assert not has_conflict
    assert merged_contents == b"common: user\n"
    assert output_path.read_text() == "common: user"


def test_merge_file_python_no_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.py"
    output_path.write_text("user_python")
    mocker.patch(
        "panther_analysis_tool.core.merge_item.git_helpers.merge_file",
        return_value=(False, b"merged_python"),
    )

    has_conflict, merged_contents = merge_item.merge_file(
        solve_merge=False,
        user=b"user_python",
        base=b"base_python",
        latest=b"base_python",
        user_python=b"user_python",
        output_path=output_path,
        editor=None,
    )
    assert not has_conflict
    assert merged_contents == b"merged_python"
    assert output_path.read_text() == "user_python"


def test_merge_file_python_conflict(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.py"
    output_path.write_text("user_python")
    mocker.patch(
        "panther_analysis_tool.core.merge_item.git_helpers.merge_file",
        return_value=(True, b"merged_python"),
    )

    has_conflict = merge_item.merge_file(
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
        "panther_analysis_tool.core.merge_item.git_helpers.merge_file",
        return_value=(True, b"merged_python"),
    )
    merge_files_mock = mocker.patch(
        "panther_analysis_tool.core.merge_item.file_editor.merge_files_in_editor",
        return_value=False,
    )
    merge_files_mock.side_effect = lambda _, **kwargs: output_path.write_text("merged_python")

    has_conflict, merged_contents = merge_item.merge_file(
        solve_merge=True,
        user=b"user_python",
        base=b"base_python",
        latest=b"base_python",
        user_python=b"user_python",
        output_path=output_path,
        editor=None,
    )
    assert not has_conflict
    assert merged_contents == b""
    assert output_path.read_text() == "merged_python"


def test_merge_file_python_conflict_auto_accept(
    mocker: MockerFixture, tmp_path: pathlib.Path
) -> None:
    output_path = tmp_path / "output.py"
    output_path.write_text("user_python")
    mocker.patch(
        "panther_analysis_tool.core.merge_item.git_helpers.merge_file",
        return_value=(False, b"user_python"),
    )

    has_conflict, merged_contents = merge_item.merge_file(
        solve_merge=False,
        user=b"user_python",
        base=b"base_python",
        latest=b"base_python",
        user_python=b"user_python",
        output_path=output_path,
        editor=None,
        auto_accept=AutoAcceptOption.YOURS,
    )
    assert not has_conflict
    assert merged_contents == b"user_python"
    assert output_path.read_text() == "user_python"


def test_merge_file_yaml_conflict_auto_accept(
    mocker: MockerFixture, tmp_path: pathlib.Path
) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user: yaml")

    has_conflict, merged_contents = merge_item.merge_file(
        solve_merge=False,
        user=b"key: user",
        base=b"key: base",
        latest=b"key: latest",
        user_python=b"",
        output_path=output_path,
        editor=None,
        auto_accept=AutoAcceptOption.YOURS,
    )
    assert not has_conflict
    assert merged_contents == b"key: user\n"
    # output file should not have changed
    assert output_path.read_text() == "user: yaml"


def test_merge_file_write_merge_conflicts(mocker: MockerFixture, tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user: yaml")

    has_conflict, merged_contents = merge_item.merge_file(
        solve_merge=False,
        user=b"key: user",
        base=b"key: base",
        latest=b"key: latest",
        user_python=b"",
        output_path=output_path,
        editor=None,
        write_merge_conflicts=True,
    )
    assert has_conflict
    assert merged_contents == b"<<<<<<< yours\nkey: user\n=======\nkey: latest\n>>>>>>> panthers\n"
    # output file should not have changed
    assert output_path.read_text() == "user: yaml"


def test_merge_file_write_merge_conflicts_and_solve_merge(
    mocker: MockerFixture, tmp_path: pathlib.Path
) -> None:
    output_path = tmp_path / "output.yml"
    output_path.write_text("user: yaml")

    has_conflict, merged_contents = merge_item.merge_file(
        solve_merge=True,
        user=b"key: user",
        base=b"key: base",
        latest=b"key: latest",
        user_python=b"",
        output_path=output_path,
        editor=None,
        write_merge_conflicts=True,
    )
    assert has_conflict
    assert merged_contents == b"<<<<<<< yours\nkey: user\n=======\nkey: latest\n>>>>>>> panthers\n"
    # output file should not have changed
    assert output_path.read_text() == "user: yaml"
