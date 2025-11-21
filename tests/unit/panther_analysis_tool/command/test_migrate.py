import pathlib

from pytest import MonkeyPatch
from pytest_mock import MockerFixture

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.command import migrate
from panther_analysis_tool.constants import (
    PANTHER_ANALYSIS_SQLITE_FILE_PATH,
    AutoAcceptOption,
)
from panther_analysis_tool.core import analysis_cache, merge_item, versions_file, yaml


def setup(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> analysis_cache.AnalysisCache:
    monkeypatch.chdir(tmp_path)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()
    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    return cache


def test_migrate_with_analysis_id(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    cache = setup(tmp_path, monkeypatch)
    rule_1_spec = {
        "AnalysisType": "rule",
        "RuleID": "fake.rule.1",
        "Filename": "fake_rule_1.py",
        "Some": "field",
    }

    mock_yaml_resolver = mocker.patch(
        "panther_analysis_tool.command.migrate.merge_item.yaml_conflict_resolver_gui.YAMLConflictResolverApp",
        return_value=mocker.MagicMock(get_final_dict=lambda: rule_1_spec | {"Some": "new value"}),
    )
    mock_merge_item = mocker.patch(
        "panther_analysis_tool.command.migrate.merge_item.git_helpers.merge_file",
        return_value=(True, b"def rule(event): return True # new version"),
    )
    mock_merge_files_in_editor = mocker.patch(
        "panther_analysis_tool.command.migrate.merge_item.file_editor.merge_files_in_editor",
        return_value=False,
    )
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.get_forked_panther_analysis_common_ancestor",
        return_value=None,
    )

    (tmp_path / "fake_rule_1.yml").write_text(yaml.dump(rule_1_spec))
    (tmp_path / "fake_rule_1.py").write_text("def rule(event): return True")
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=None,
            spec=yaml.dump(rule_1_spec | {"Some": "new value"}).encode("utf-8"),
            version=1,
            id_field="RuleID",
            id_value="fake.rule.1",
        ),
        b"def rule(event): return True # new version",
    )

    migration_output = tmp_path / "migration_output.md"
    migration_output.touch()

    result = migrate.migrate("fake.rule.1", None, migration_output, None)
    assert not result.empty()
    assert len(result.items_migrated) == 1
    assert len(result.items_with_conflicts) == 0
    assert (
        migration_output.read_text()
        == """# Migration Results

## Analysis Items Migrated

1 analysis item(s) migrated.

### Analysis Type: rule

1 analysis item(s) migrated.

  * fake.rule.1

"""
    )
    assert mock_yaml_resolver.call_count == 1
    assert mock_merge_item.call_count == 1
    assert mock_merge_files_in_editor.call_count == 1


#######################################################################################
### Test get_items_to_migrate
#######################################################################################


def test_get_items_to_migrate_has_base_version(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    cache = setup(tmp_path, monkeypatch)
    (tmp_path / "fake_rule_1.yml").write_text(
        yaml.dump(
            {
                "AnalysisType": "rule",
                "RuleID": "fake.rule.1",
                "BaseVersion": 1,
            }
        )
    )

    specs = list(analysis_utils.load_analysis_specs_ex([str(tmp_path)], [], True))
    assert len(specs) == 1
    item = migrate.get_migration_item(specs[0], None, cache)
    assert item is None


def test_get_items_to_migrate_no_latest_spec(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    cache = setup(tmp_path, monkeypatch)
    (tmp_path / "fake_rule_1.yml").write_text(
        yaml.dump(
            {
                "AnalysisType": "rule",
                "RuleID": "fake.rule.1",
            }
        )
    )

    specs = list(analysis_utils.load_analysis_specs_ex([str(tmp_path)], [], True))
    assert len(specs) == 1
    item = migrate.get_migration_item(specs[0], None, cache)
    assert item is None


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

    specs = list(analysis_utils.load_analysis_specs_ex([str(tmp_path)], [], True))
    assert len(specs) == 2

    items = [migrate.get_migration_item(spec, None, cache) for spec in specs]
    assert len(items) == 2
    assert items[0] is not None
    assert items[1] is not None

    assert items[0].user_item.yaml_file_contents == rule_1_dict
    assert items[0].user_item.raw_yaml_file_contents == rule_1_spec.encode("utf-8")
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

    assert items[1].user_item.yaml_file_contents == rule_2_dict
    assert items[1].user_item.raw_yaml_file_contents == rule_2_spec.encode("utf-8")
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


def test_get_item_to_migrate_with_remote_base(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    cache = setup(tmp_path, monkeypatch)

    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.get_file_at_commit",
        side_effect=[b"fake: yaml", b"from fake import python"],
    )

    py = "def rule(event): return True"
    rule_1_dict = {
        "AnalysisType": "rule",
        "RuleID": "fake.rule.1",
        "Filename": "fake_rule_1.py",
    }
    rule_1_spec = yaml.dump(rule_1_dict)
    (tmp_path / "fake_rule_1.yml").write_text(rule_1_spec)
    (tmp_path / "fake_rule_1.py").write_text(py)
    (tmp_path / versions_file.CACHED_VERSIONS_FILE_PATH).write_text(
        yaml.dump(
            {
                "versions": {
                    "fake.rule.1": {
                        "version": 1,
                        "type": "rule",
                        "sha256": "fake.sha256",
                        "history": {
                            "1": {
                                "version": 1,
                                "commit_hash": "fake.commit.1",
                                "yaml_file_path": "fake_rule_1.yml",
                                "py_file_path": "fake_rule_1.py",
                            },
                        },
                    },
                },
            }
        )
    )
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=None,
            spec=rule_1_spec.encode("utf-8"),
            version=1,
            id_field="RuleID",
            id_value="fake.rule.1",
        ),
        b"def rule(event): return True",
    )

    specs = list(analysis_utils.load_analysis_specs_ex([str(tmp_path)], [], True))
    assert len(specs) == 1

    item = migrate.get_migration_item(
        user_spec=specs[0],
        analysis_id=None,
        cache=cache,
        ancestor_commit="fake.commit.1",
    )

    assert item is not None

    assert item.user_item.yaml_file_contents == rule_1_dict
    assert item.user_item.raw_yaml_file_contents == rule_1_spec.encode("utf-8")
    assert item.user_item.yaml_file_path == str(tmp_path / "fake_rule_1.yml")
    assert item.user_item.python_file_contents == b"def rule(event): return True"
    assert item.user_item.python_file_path == str(tmp_path / "fake_rule_1.py")

    assert item.base_panther_item.yaml_file_contents == {"fake": "yaml"}
    assert item.base_panther_item.raw_yaml_file_contents == b"fake: yaml"
    assert item.base_panther_item.yaml_file_path is None
    assert item.base_panther_item.python_file_contents == b"from fake import python"
    assert item.base_panther_item.python_file_path is None

    assert item.latest_panther_item.yaml_file_contents == rule_1_dict
    assert item.latest_panther_item.raw_yaml_file_contents == rule_1_spec.encode("utf-8")
    assert item.latest_panther_item.yaml_file_path is None
    assert item.latest_panther_item.python_file_contents == py.encode("utf-8")
    assert item.latest_panther_item.python_file_path is None


#######################################################################################
### Test migrate_items
#######################################################################################


def test_migrate_items_no_conflicts(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "fake_rule_1.yml").write_text(
        yaml.dump({"AnalysisType": "rule", "RuleID": "fake.rule.1"})
    )
    (tmp_path / "fake_rule_2.yml").write_text(
        yaml.dump({"AnalysisType": "rule", "RuleID": "fake.rule.2"})
    )

    mock_merge_item = mocker.patch(
        "panther_analysis_tool.command.migrate.merge_item.merge_item", side_effect=[False, False]
    )

    items = [
        merge_item.MergeableItem(
            user_item=analysis_utils.AnalysisItem(
                yaml_file_contents={"AnalysisType": "rule", "RuleID": "fake.rule.1"},
                yaml_file_path=str(tmp_path / "fake_rule_1.yml"),
            ),
            latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            latest_item_version=1,
        ),
        merge_item.MergeableItem(
            user_item=analysis_utils.AnalysisItem(
                yaml_file_contents={"AnalysisType": "rule", "RuleID": "fake.rule.2"},
                yaml_file_path=str(tmp_path / "fake_rule_2.yml"),
            ),
            latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            latest_item_version=1,
        ),
    ]

    result = migrate.MigrationResult(items_with_conflicts=[], items_migrated=[])
    for item in items:
        migrate.migrate_item(item, False, None, result)
    assert len(result.items_with_conflicts) == 0
    assert len(result.items_migrated) == 2
    assert mock_merge_item.call_count == 2
    assert (
        tmp_path / "fake_rule_1.yml"
    ).read_text() == "AnalysisType: rule\nRuleID: fake.rule.1\nBaseVersion: 1\n"
    assert (
        tmp_path / "fake_rule_2.yml"
    ).read_text() == "AnalysisType: rule\nRuleID: fake.rule.2\nBaseVersion: 1\n"


def test_migrate_items_with_conflicts(mocker: MockerFixture) -> None:
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

    result = migrate.MigrationResult(items_with_conflicts=[], items_migrated=[])
    for item in items:
        migrate.migrate_item(item, False, None, result)
    assert len(result.items_with_conflicts) == 2
    assert len(result.items_migrated) == 0
    assert mock_merge_item.call_count == 2


def test_migrate_items_with_conflicts_accept_yours(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "fake_rule_1.yml").write_text(
        yaml.dump({"AnalysisType": "rule", "RuleID": "fake.rule.1"})
    )
    (tmp_path / "fake_rule_2.yml").write_text(
        yaml.dump({"AnalysisType": "rule", "RuleID": "fake.rule.2"})
    )

    mock_merge_item = mocker.patch(
        "panther_analysis_tool.command.migrate.merge_item.merge_item", side_effect=[False, False]
    )

    items = [
        merge_item.MergeableItem(
            user_item=analysis_utils.AnalysisItem(
                yaml_file_contents={"AnalysisType": "rule", "RuleID": "fake.rule.1"},
                yaml_file_path=str(tmp_path / "fake_rule_1.yml"),
            ),
            latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            latest_item_version=1,
        ),
        merge_item.MergeableItem(
            user_item=analysis_utils.AnalysisItem(
                yaml_file_contents={"AnalysisType": "rule", "RuleID": "fake.rule.2"},
                yaml_file_path=str(tmp_path / "fake_rule_2.yml"),
            ),
            latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
            latest_item_version=1,
        ),
    ]

    result = migrate.MigrationResult(items_with_conflicts=[], items_migrated=[])
    for item in items:
        migrate.migrate_item(item, False, None, result, AutoAcceptOption.YOURS)
    assert len(result.items_with_conflicts) == 0
    assert len(result.items_migrated) == 2
    assert mock_merge_item.call_count == 2
    assert (
        tmp_path / "fake_rule_1.yml"
    ).read_text() == "AnalysisType: rule\nRuleID: fake.rule.1\nBaseVersion: 1\n"
    assert (
        tmp_path / "fake_rule_2.yml"
    ).read_text() == "AnalysisType: rule\nRuleID: fake.rule.2\nBaseVersion: 1\n"


#######################################################################################
### Test write_migration_results
#######################################################################################


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
