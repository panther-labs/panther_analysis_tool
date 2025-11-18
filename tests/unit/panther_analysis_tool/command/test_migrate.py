import pathlib

from pytest import MonkeyPatch
from pytest_mock import MockerFixture

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.command import migrate
from panther_analysis_tool.constants import PANTHER_ANALYSIS_SQLITE_FILE_PATH
from panther_analysis_tool.core import analysis_cache, merge_item, yaml


def setup(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> analysis_cache.AnalysisCache:
    monkeypatch.chdir(tmp_path)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()
    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    return cache


def test_get_items_to_migrate_has_base_version(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    setup(tmp_path, monkeypatch)
    (tmp_path / "fake_rule_1.yml").write_text(
        yaml.dump(
            {
                "AnalysisType": "rule",
                "RuleID": "fake.rule.1",
                "BaseVersion": 1,
            }
        )
    )

    items = migrate.get_items_to_migrate(None)
    assert len(items) == 0


def test_get_items_to_migrate_no_latest_spec(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    setup(tmp_path, monkeypatch)
    (tmp_path / "fake_rule_1.yml").write_text(
        yaml.dump(
            {
                "AnalysisType": "rule",
                "RuleID": "fake.rule.1",
            }
        )
    )

    items = migrate.get_items_to_migrate(None)
    assert len(items) == 0


def test_get_items_to_migrate(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = setup(tmp_path, monkeypatch)
    rule_1_dict = {
        "AnalysisType": "rule",
        "RuleID": "fake.rule.1",
        "Filename": "fake_rule_1.py",
    }
    rule_1_spec = yaml.dump(rule_1_dict)
    rule_2_dict = {
        "AnalysisType": "rule",
        "RuleID": "fake.rule.2",
        "Filename": "fake_rule_2.py",
    }
    rule_2_spec = yaml.dump(rule_2_dict)
    (tmp_path / "fake_rule_1.yml").write_text(rule_1_spec)
    (tmp_path / "fake_rule_2.yml").write_text(rule_2_spec)
    (tmp_path / "fake_rule_1.py").write_text("def rule(event): return True")
    (tmp_path / "fake_rule_2.py").write_text("def rule(event): return True")
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=None,
            spec=rule_1_spec.encode("utf-8"),
            version=1,
            id_field="RuleID",
            id_value="fake.rule.1",
        ),
        b"def rule(event): return True # new version",
    )
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=None,
            spec=rule_2_spec.encode("utf-8"),
            version=1,
            id_field="RuleID",
            id_value="fake.rule.2",
        ),
        b"def rule(event): return True # new version",
    )

    items = migrate.get_items_to_migrate(None)
    assert len(items) == 2

    assert items[0].user_item.yaml_file_contents == rule_1_dict | {"BaseVersion": 1}
    assert items[0].user_item.raw_yaml_file_contents == (rule_1_spec + "BaseVersion: 1\n").encode(
        "utf-8"
    )
    assert items[0].user_item.python_file_contents == b"def rule(event): return True"
    assert items[0].user_item.python_file_path == str(tmp_path / "fake_rule_1.py")
    assert items[0].latest_panther_item.yaml_file_contents == rule_1_dict
    assert items[0].latest_panther_item.raw_yaml_file_contents == rule_1_spec.encode("utf-8")
    assert (
        items[0].latest_panther_item.python_file_contents
        == b"def rule(event): return True # new version"
    )
    assert items[0].latest_panther_item.python_file_path is None
    assert items[0].base_panther_item.yaml_file_contents == {}
    assert items[0].base_panther_item.python_file_contents is None
    assert items[0].base_panther_item.python_file_path is None

    assert items[1].user_item.yaml_file_contents == rule_2_dict | {"BaseVersion": 1}
    assert items[1].user_item.raw_yaml_file_contents == (rule_2_spec + "BaseVersion: 1\n").encode(
        "utf-8"
    )
    assert items[1].user_item.python_file_contents == b"def rule(event): return True"
    assert items[1].user_item.python_file_path == str(tmp_path / "fake_rule_2.py")
    assert items[1].latest_panther_item.yaml_file_contents == rule_2_dict
    assert items[1].latest_panther_item.raw_yaml_file_contents == rule_2_spec.encode("utf-8")
    assert (
        items[1].latest_panther_item.python_file_contents
        == b"def rule(event): return True # new version"
    )
    assert items[1].latest_panther_item.python_file_path is None
    assert items[1].base_panther_item.yaml_file_contents == {}
    assert items[1].base_panther_item.python_file_contents is None
    assert items[1].base_panther_item.python_file_path is None


def test_migrate_items_no_conflicts(tmp_path: pathlib.Path, mocker: MockerFixture) -> None:
    mock_merge_item = mocker.patch(
        "panther_analysis_tool.command.migrate.merge_item.merge_item", side_effect=[False, False]
    )

    items = [
        merge_item.MergeableItem(
            user_item=analysis_utils.AnalysisItem(
                yaml_file_contents={"AnalysisType": "rule", "RuleID": "fake.rule.1"}
            ),
            latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        ),
        merge_item.MergeableItem(
            user_item=analysis_utils.AnalysisItem(
                yaml_file_contents={"AnalysisType": "rule", "RuleID": "fake.rule.2"}
            ),
            latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        ),
    ]

    result = migrate.migrate_items(items, False, None)
    assert len(result.items_with_conflicts) == 0
    assert len(result.items_migrated) == 2
    assert mock_merge_item.call_count == 2


def test_migrate_items_with_conflicts(tmp_path: pathlib.Path, mocker: MockerFixture) -> None:
    mock_merge_item = mocker.patch(
        "panther_analysis_tool.command.migrate.merge_item.merge_item", side_effect=[True, True]
    )

    items = [
        merge_item.MergeableItem(
            user_item=analysis_utils.AnalysisItem(
                yaml_file_contents={"AnalysisType": "rule", "RuleID": "fake.rule.1"}
            ),
            latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        ),
        merge_item.MergeableItem(
            user_item=analysis_utils.AnalysisItem(
                yaml_file_contents={"AnalysisType": "rule", "RuleID": "fake.rule.2"}
            ),
            latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        ),
    ]

    result = migrate.migrate_items(items, False, None)
    assert len(result.items_with_conflicts) == 2
    assert len(result.items_migrated) == 0
    assert mock_merge_item.call_count == 2


def test_write_migration_results_empty(tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "migration_output.md"
    output_path.touch()

    migrate.write_migration_results(
        migrate.MigrationResult(
            items_with_conflicts=[],
            items_migrated=[],
        ),
        output_path,
    )

    assert output_path.read_text() == ""


def test_write_migration_results_no_conflicts(tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "migration_output.md"
    output_path.touch()

    migrate.write_migration_results(
        migrate.MigrationResult(
            items_with_conflicts=[],
            items_migrated=[
                migrate.MigrationItem(analysis_id="fake.rule.1", analysis_type="rule"),
                migrate.MigrationItem(analysis_id="fake.rule.2", analysis_type="rule"),
                migrate.MigrationItem(analysis_id="fake.policy.1", analysis_type="policy"),
                migrate.MigrationItem(analysis_id="fake.policy.2", analysis_type="policy"),
            ],
        ),
        output_path,
    )

    assert (
        output_path.read_text()
        == """# Migration Results

## Analysis Items Migrated

4 analysis item(s) migrated.

### Analysis Type: rule

2 analysis item(s) migrated.

  * fake.rule.1
  * fake.rule.2

### Analysis Type: policy

2 analysis item(s) migrated.

  * fake.policy.1
  * fake.policy.2

"""
    )


def test_write_migration_results_with_conflicts_only(tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "migration_output.md"
    output_path.touch()

    migrate.write_migration_results(
        migrate.MigrationResult(
            items_with_conflicts=[
                migrate.MigrationItem(analysis_id="fake.rule.1", analysis_type="rule"),
                migrate.MigrationItem(analysis_id="fake.rule.2", analysis_type="rule"),
                migrate.MigrationItem(analysis_id="fake.policy.1", analysis_type="policy"),
                migrate.MigrationItem(analysis_id="fake.policy.2", analysis_type="policy"),
            ],
            items_migrated=[],
        ),
        output_path,
    )

    assert (
        output_path.read_text()
        == """# Migration Results

## Analysis Items with Merge Conflicts

4 merge conflict(s) found. Run `EDITOR=<editor> pat migrate <id>` to resolve each conflict.

### Analysis Type: rule

2 merge conflict(s).

  * fake.rule.1
  * fake.rule.2

### Analysis Type: policy

2 merge conflict(s).

  * fake.policy.1
  * fake.policy.2

"""
    )


def test_write_migration_results(tmp_path: pathlib.Path) -> None:
    output_path = tmp_path / "migration_output.md"
    output_path.touch()

    migrate.write_migration_results(
        migrate.MigrationResult(
            items_with_conflicts=[
                migrate.MigrationItem(analysis_id="fake.rule.1", analysis_type="rule"),
                migrate.MigrationItem(analysis_id="fake.rule.2", analysis_type="rule"),
                migrate.MigrationItem(analysis_id="fake.policy.1", analysis_type="policy"),
                migrate.MigrationItem(analysis_id="fake.policy.2", analysis_type="policy"),
            ],
            items_migrated=[
                migrate.MigrationItem(analysis_id="fake.rule.1", analysis_type="rule"),
                migrate.MigrationItem(analysis_id="fake.rule.2", analysis_type="rule"),
                migrate.MigrationItem(analysis_id="fake.policy.1", analysis_type="policy"),
                migrate.MigrationItem(analysis_id="fake.policy.2", analysis_type="policy"),
            ],
        ),
        output_path,
    )

    assert (
        output_path.read_text()
        == """# Migration Results

## Analysis Items with Merge Conflicts

4 merge conflict(s) found. Run `EDITOR=<editor> pat migrate <id>` to resolve each conflict.

### Analysis Type: rule

2 merge conflict(s).

  * fake.rule.1
  * fake.rule.2

### Analysis Type: policy

2 merge conflict(s).

  * fake.policy.1
  * fake.policy.2

## Analysis Items Migrated

4 analysis item(s) migrated.

### Analysis Type: rule

2 analysis item(s) migrated.

  * fake.rule.1
  * fake.rule.2

### Analysis Type: policy

2 analysis item(s) migrated.

  * fake.policy.1
  * fake.policy.2

"""
    )
