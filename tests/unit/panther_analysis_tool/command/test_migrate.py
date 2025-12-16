import io
import json
import pathlib

from pytest import MonkeyPatch
from pytest_mock import MockerFixture

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.command import migrate
from panther_analysis_tool.constants import (
    CACHED_MIGRATION_STATUS_FILE_PATH,
    CACHED_VERSIONS_FILE_PATH,
    MIGRATION_STATUS_FILE_PATH,
    PANTHER_ANALYSIS_SQLITE_FILE_PATH,
    AutoAcceptOption,
)
from panther_analysis_tool.core import analysis_cache, merge_item, versions_file, yaml


def create_fake_versions_file(ids: list[tuple[str, int]]) -> dict:
    versions = {}
    for id_, version in ids:
        versions[id_] = {
            "version": version,
            "type": "rule",
            "sha256": "fake.sha256",
            "history": {
                version: {
                    "version": version,
                    "commit_hash": "fake.commit.1",
                    "yaml_file_path": f"{id_.replace('.', '_')}.yml",
                    "py_file_path": f"{id_.replace('.', '_')}.py",
                },
            },
        }
    return {"versions": versions}


def create_migration_status_markdown(
    migrated: list[str], conflicts: list[str], deleted: list[tuple[str, str]]
) -> str:
    """
    Testing the output of the migration status markdown can make tests hard to read.
    So this function creates the expected markdown so the tests can be more readable.
    """
    if len(migrated) == 0 and len(conflicts) == 0 and len(deleted) == 0:
        return ""

    markdown = io.StringIO()
    markdown.write("# Migration Results\n\n")
    markdown.write("## Migration Summary\n\n")
    markdown.write(f"  * {len(conflicts)} merge conflict(s) found.\n")
    markdown.write(f"  * {len(deleted)} analysis item(s) deleted.\n")
    markdown.write(f"  * {len(migrated)} analysis item(s) migrated.\n\n")

    if len(conflicts) > 0:
        markdown.write("## Analysis Items with Merge Conflicts\n\n")
        markdown.write(
            f"{len(conflicts)} merge conflict(s) found. Run `EDITOR=<editor> pat migrate <id>` to resolve each conflict.\n\n"
        )
        for conflict in conflicts:
            markdown.write(f"  * {conflict}\n")
        markdown.write("\n")

    if len(deleted) > 0:
        markdown.write("## Analysis Items Deleted\n\n")
        markdown.write(f"{len(deleted)} analysis item(s) deleted.\n\n")
        for item in deleted:
            markdown.write(f"  * {item[0]} - {item[1]}\n")
        markdown.write("\n")

    if len(migrated) > 0:
        markdown.write("## Analysis Items Migrated\n\n")
        markdown.write(f"{len(migrated)} analysis item(s) migrated.\n\n")
        for item in migrated:  # type: ignore
            markdown.write(f"  * {item}\n")
        markdown.write("\n")

    return markdown.getvalue()


def setup(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> analysis_cache.AnalysisCache:
    monkeypatch.chdir(tmp_path)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()
    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    return cache


def test_migrate_deletes_items(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.git_root",
        return_value=str(tmp_path),
    )
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.get_forked_panther_analysis_common_ancestor",
        return_value="abc123",
    )
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.get_file_at_commit",
        side_effect=[
            b"{RuleID: fake.rule.1}",
            b"",
            b"{RuleID: fake.rule.2}",
            b"",
            b"{RuleID: fake.rule.to.delete}",
            b"",
        ],
    )
    cache = setup(tmp_path, monkeypatch)

    rule_1_spec = {
        "AnalysisType": "rule",
        "RuleID": "fake.rule.1",
        "Filename": "fake_rule_1.py",
        "Enabled": True,
    }
    rule_2_spec = {
        "AnalysisType": "rule",
        "RuleID": "fake.rule.2",
        "Filename": "fake_rule_2.py",
        "Enabled": False,
    }
    rule_to_delete_spec = {
        "AnalysisType": "rule",
        "RuleID": "fake.rule.to.delete",
        "Filename": "fake_rule_to_delete.py",
        "Enabled": False,
    }
    pack_spec = {
        "AnalysisType": "pack",
        "PackID": "fake.pack.1",
    }

    (tmp_path / "fake_rule_1.yml").write_text(yaml.dump(rule_1_spec))
    (tmp_path / "fake_rule_1.py").write_text("def rule(event): return True")
    (tmp_path / "fake_rule_2.yml").write_text(yaml.dump(rule_2_spec))
    (tmp_path / "fake_rule_2.py").write_text("def rule(event): return True")
    (tmp_path / "fake_rule_to_delete.yml").write_text(yaml.dump(rule_to_delete_spec))
    (tmp_path / "fake_rule_to_delete.py").write_text("def rule(event): return True")
    (tmp_path / "fake_pack_1.yml").write_text(yaml.dump(pack_spec))
    (tmp_path / CACHED_VERSIONS_FILE_PATH).write_text(
        yaml.dump(
            {
                "versions": {},
            }
        )
    )

    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=None,
            spec=yaml.dump(rule_1_spec).encode("utf-8"),
            version=1,
            id_field="RuleID",
            id_value="fake.rule.1",
        ),
        b"def rule(event): return True",
    )
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=None,
            spec=yaml.dump(rule_2_spec).encode("utf-8"),
            version=1,
            id_field="RuleID",
            id_value="fake.rule.2",
        ),
        b"def rule(event): return True",
    )

    result = migrate.migrate(None, None, None)
    assert len(result.items_deleted) == 2
    fake_pack_1_item = result.items_deleted["fake.pack.1"]
    assert fake_pack_1_item.analysis_id == "fake.pack.1"
    assert fake_pack_1_item.pretty_analysis_type == "Pack"
    assert fake_pack_1_item.reason == "Packs are managed by Panther and not needed in your repo."
    fake_rule_to_delete_item = result.items_deleted["fake.rule.to.delete"]
    assert fake_rule_to_delete_item.analysis_id == "fake.rule.to.delete"
    assert fake_rule_to_delete_item.pretty_analysis_type == "Rule"
    assert (
        fake_rule_to_delete_item.reason
        == "Item was deleted by Panther since your last update and was disabled in your repo."
    )

    assert len(result.items_migrated) == 2
    fake_rule_1_item = result.items_migrated["fake.rule.1"]
    assert fake_rule_1_item.analysis_id == "fake.rule.1"
    assert fake_rule_1_item.pretty_analysis_type == "Rule"
    fake_rule_2_item = result.items_migrated["fake.rule.2"]
    assert fake_rule_2_item.analysis_id == "fake.rule.2"
    assert fake_rule_2_item.pretty_analysis_type == "Rule"
    assert len(result.items_with_conflicts) == 0

    assert not (tmp_path / "fake_rule_to_delete.yml").exists()
    assert not (tmp_path / "fake_rule_to_delete.py").exists()
    assert not (tmp_path / "fake_pack_1.yml").exists()

    assert (tmp_path / "fake_rule_1.yml").exists()
    assert (tmp_path / "fake_rule_1.py").exists()
    assert (tmp_path / "fake_rule_2.yml").exists()
    assert (tmp_path / "fake_rule_2.py").exists()


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
    (tmp_path / versions_file.CACHED_VERSIONS_FILE_PATH).write_text(
        yaml.dump(create_fake_versions_file([("fake.rule.1", 1)]))
    )

    result = migrate.migrate("fake.rule.1", None, None)
    assert not result.empty()
    assert len(result.items_migrated) == 1
    assert len(result.items_with_conflicts) == 0
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).exists()
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).read_text() == create_migration_status_markdown(
        ["(Rule) fake.rule.1"], [], []
    )
    assert mock_yaml_resolver.call_count == 1
    assert mock_merge_item.call_count == 1
    assert mock_merge_files_in_editor.call_count == 1


def test_migrate_changes_migration_status(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    cache = setup(tmp_path, monkeypatch)
    rule_1_spec = {
        "AnalysisType": "rule",
        "RuleID": "fake.rule.1",
        "Filename": "fake_rule_1.py",
    }
    rule_2_spec = {
        "AnalysisType": "rule",
        "RuleID": "fake.rule.2",
        "Filename": "fake_rule_2.py",
        "Some": "old value",
    }
    rule_py = "def rule(event): return True"
    pack_spec = {
        "AnalysisType": "pack",
        "PackID": "fake.pack.1",
        "Filename": "fake_pack_1.py",
    }

    mocker.patch(
        "panther_analysis_tool.command.migrate.merge_item.merge_item",
        side_effect=[
            False,  # first run, no conflict for rule 1
            True,  # first run, conflict for rule 2
            True,  # second run, not called for rule 1, conflict for rule 2
            False,  # third run, not called for rule 1, no conflict for rule 2 since it resolved
            # not called on fourth run
            # not called on fifth run
        ],
    )
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.get_forked_panther_analysis_common_ancestor",
        return_value=None,
    )

    (tmp_path / "fake_rule_1.yml").write_text(yaml.dump(rule_1_spec))
    (tmp_path / "fake_rule_1.py").write_text(rule_py)
    (tmp_path / "fake_rule_2.yml").write_text(yaml.dump(rule_2_spec))
    (tmp_path / "fake_rule_2.py").write_text(rule_py)
    (tmp_path / "fake_pack_1.yml").write_text(yaml.dump(pack_spec))
    (tmp_path / "fake_pack_1.py").write_text(rule_py)
    (tmp_path / versions_file.CACHED_VERSIONS_FILE_PATH).write_text(
        yaml.dump(create_fake_versions_file([("fake.rule.1", 1), ("fake.rule.2", 1)]))
    )

    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=None,
            spec=yaml.dump(rule_1_spec | {"Some": "new value"}).encode("utf-8"),
            version=1,
            id_field="RuleID",
            id_value="fake.rule.1",
        ),
        rule_py.encode("utf-8"),
    )
    cache.insert_analysis_spec(
        analysis_cache.AnalysisSpec(
            id=None,
            spec=yaml.dump(rule_2_spec | {"Some": "new value"}).encode("utf-8"),
            version=1,
            id_field="RuleID",
            id_value="fake.rule.2",
        ),
        rule_py.encode("utf-8"),
    )

    # first run
    result = migrate.migrate(None, None)
    assert not result.empty()
    assert len(result.items_migrated) == 1
    assert len(result.items_with_conflicts) == 1
    assert len(result.items_deleted) == 1
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).exists()
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).read_text() == create_migration_status_markdown(
        ["(Rule) fake.rule.1"],
        ["(Rule) fake.rule.2"],
        [("(Pack) fake.pack.1", "Packs are managed by Panther and not needed in your repo.")],
    )

    # second run, should not change anything
    result = migrate.migrate(None, None)
    assert not result.empty()
    assert len(result.items_migrated) == 1
    assert len(result.items_with_conflicts) == 1
    assert len(result.items_deleted) == 1
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).exists()
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).read_text() == create_migration_status_markdown(
        ["(Rule) fake.rule.1"],
        ["(Rule) fake.rule.2"],
        [("(Pack) fake.pack.1", "Packs are managed by Panther and not needed in your repo.")],
    )

    # third run, only on rule 2 to simulate resolving the conflict, should move item
    result = migrate.migrate("fake.rule.2", None)
    assert not result.empty()
    assert len(result.items_migrated) == 2
    assert len(result.items_with_conflicts) == 0
    assert len(result.items_deleted) == 1
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).exists()
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).read_text() == create_migration_status_markdown(
        ["(Rule) fake.rule.1", "(Rule) fake.rule.2"],
        [],
        [("(Pack) fake.pack.1", "Packs are managed by Panther and not needed in your repo.")],
    )

    # fourth run, only on rule 2, should not change anything
    result = migrate.migrate("fake.rule.2", None)
    assert not result.empty()
    assert len(result.items_migrated) == 2
    assert len(result.items_with_conflicts) == 0
    assert len(result.items_deleted) == 1
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).exists()
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).read_text() == create_migration_status_markdown(
        ["(Rule) fake.rule.1", "(Rule) fake.rule.2"],
        [],
        [("(Pack) fake.pack.1", "Packs are managed by Panther and not needed in your repo.")],
    )

    # fifth run, should not change anything
    result = migrate.migrate(None, None)
    assert not result.empty()
    assert len(result.items_migrated) == 2
    assert len(result.items_with_conflicts) == 0
    assert len(result.items_deleted) == 1
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).exists()
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).read_text() == create_migration_status_markdown(
        ["(Rule) fake.rule.1", "(Rule) fake.rule.2"],
        [],
        [("(Pack) fake.pack.1", "Packs are managed by Panther and not needed in your repo.")],
    )


#######################################################################################
### Test get_migration_item
#######################################################################################


def test_get_migration_item_has_base_version(
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
    result = migrate.MigrationStatus()
    item = migrate.get_migration_item(specs[0], None, cache, result)
    assert item is None


def test_get_migration_item_no_latest_spec(
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
    result = migrate.MigrationStatus()
    item = migrate.get_migration_item(specs[0], None, cache, result)
    assert item is None


def test_get_migration_item(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
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

    result = migrate.MigrationStatus()
    items = [migrate.get_migration_item(spec, None, cache, result) for spec in specs]
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


def test_get_migration_item_with_remote_base(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    cache = setup(tmp_path, monkeypatch)

    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.get_file_at_commit",
        side_effect=[b"fake: yaml", b"from fake import python"],
    )
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.git_root",
        return_value=str(tmp_path),
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
        yaml.dump(create_fake_versions_file([("fake.rule.1", 1)]))
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

    result = migrate.MigrationStatus()
    item = migrate.get_migration_item(
        user_spec=specs[0],
        analysis_id=None,
        cache=cache,
        result=result,
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


def test_get_migration_item_pack(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    cache = setup(tmp_path, monkeypatch)
    rule_1_dict = {
        "AnalysisType": "pack",
        "PackID": "fake.pack.1",
        "PackDefinition": {
            "IDs": ["fake.rule.1"],
        },
    }
    rule_1_spec = yaml.dump(rule_1_dict)
    (tmp_path / "fake_pack_1.yml").write_text(rule_1_spec)

    specs = list(analysis_utils.load_analysis_specs_ex([str(tmp_path)], [], True))
    assert len(specs) == 1

    result = migrate.MigrationStatus()
    item = migrate.get_migration_item(specs[0], None, cache, result)
    assert item is None


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

    result = migrate.MigrationStatus()
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

    result = migrate.MigrationStatus()
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

    result = migrate.MigrationStatus()
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


def test_migrate_item_write_merge_conflicts(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "fake_rule_1.yml").write_text(
        yaml.dump({"AnalysisType": "rule", "RuleID": "fake.rule.1", "Filename": "fake_rule_1.py"})
    )

    mocker.patch("panther_analysis_tool.command.migrate.merge_item.merge_item", side_effect=[True])

    item = merge_item.MergeableItem(
        user_item=analysis_utils.AnalysisItem(
            yaml_file_contents={
                "AnalysisType": "rule",
                "RuleID": "fake.rule.1",
                "Filename": "fake_rule_1.py",
            },
            yaml_file_path=str(tmp_path / "fake_rule_1.yml"),
            raw_yaml_file_contents=b"AnalysisType: rule\nRuleID: fake.rule.1\nFilename: fake_rule_1.py\n",
            python_file_contents=b"def rule(event): return True",
            python_file_path=str(tmp_path / "fake_rule_1.py"),
        ),
        latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        latest_item_version=1,
    )

    result = migrate.MigrationResult()
    migrate.migrate_item(
        item=item,
        solve_merge=False,
        editor=None,
        migration_result=result,
        write_merge_conflicts=True,
    )

    assert result.items_with_conflicts == [
        migrate.MigrationItem(analysis_id="fake.rule.1", pretty_analysis_type="Rule")
    ]
    assert result.items_migrated == []
    assert result.items_deleted == []
    assert (
        tmp_path / "fake_rule_1.yml"
    ).read_text() == "AnalysisType: rule\nRuleID: fake.rule.1\nFilename: fake_rule_1.py\nBaseVersion: 1\n"


#######################################################################################
### Test ensure_python_file_exists
#######################################################################################


def test_ensure_python_file_exists(tmp_path: pathlib.Path, mocker: MockerFixture) -> None:
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.git_root",
        return_value=str(tmp_path),
    )
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.get_file_at_commit",
        return_value=b"def rule(event): return True",
    )

    rule_path = tmp_path / "rules" / "fake_rules"

    item = merge_item.MergeableItem(
        user_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        merged_item=analysis_utils.AnalysisItem(
            yaml_file_contents={
                "AnalysisType": "rule",
                "RuleID": "fake.rule.1",
                "Filename": "fake_rule_1.py",
            },
            yaml_file_path=str(rule_path / "fake_rule_1.yml"),
        ),
    )

    migrate.ensure_python_file_exists(item)
    assert item.merged_item is not None
    assert item.merged_item.python_file_contents == b"def rule(event): return True"
    assert item.merged_item.python_file_path == str(rule_path / "fake_rule_1.py")
    assert (rule_path / "fake_rule_1.py").exists()
    assert (rule_path / "fake_rule_1.py").read_bytes() == b"def rule(event): return True"


def test_ensure_python_file_exists_no_merged_item(
    tmp_path: pathlib.Path, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.git_root",
        return_value=str(tmp_path),
    )
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.get_file_at_commit",
        return_value=b"def rule(event): return True",
    )

    rule_path = tmp_path / "rules" / "fake_rules"

    item = merge_item.MergeableItem(
        user_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        merged_item=None,
    )

    migrate.ensure_python_file_exists(item)
    assert item.merged_item is None
    assert not (rule_path / "fake_rule_1.py").exists()


def test_ensure_python_file_exists_no_filename(
    tmp_path: pathlib.Path, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.git_root",
        return_value=str(tmp_path),
    )
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.get_file_at_commit",
        return_value=b"def rule(event): return True",
    )

    rule_path = tmp_path / "rules" / "fake_rules"

    item = merge_item.MergeableItem(
        user_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        merged_item=analysis_utils.AnalysisItem(
            yaml_file_contents={
                "AnalysisType": "rule",
                "RuleID": "fake.rule.1",
            },
            yaml_file_path=str(rule_path / "fake_rule_1.yml"),
        ),
    )

    migrate.ensure_python_file_exists(item)
    assert item.merged_item is not None
    assert not (rule_path / "fake_rule_1.py").exists()


def test_ensure_python_file_exists_python_exists(
    tmp_path: pathlib.Path, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.git_root",
        return_value=str(tmp_path),
    )

    rule_path = tmp_path / "rules" / "fake_rules"
    rule_path.mkdir(parents=True, exist_ok=True)
    (rule_path / "fake_rule_1.py").write_bytes(b"def rule(event): return True")
    item = merge_item.MergeableItem(
        user_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        merged_item=analysis_utils.AnalysisItem(
            yaml_file_contents={
                "AnalysisType": "rule",
                "RuleID": "fake.rule.1",
            },
            yaml_file_path=str(rule_path / "fake_rule_1.yml"),
        ),
    )

    migrate.ensure_python_file_exists(item)
    assert item.merged_item is not None
    assert (rule_path / "fake_rule_1.py").exists()


def test_ensure_python_file_exists_nothing_in_remote(
    tmp_path: pathlib.Path, mocker: MockerFixture
) -> None:
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.git_root",
        return_value=str(tmp_path),
    )
    mocker.patch(
        "panther_analysis_tool.command.migrate.git_helpers.get_file_at_commit",
        return_value=None,
    )

    rule_path = tmp_path / "rules" / "fake_rules"

    item = merge_item.MergeableItem(
        user_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        latest_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        base_panther_item=analysis_utils.AnalysisItem(yaml_file_contents={}),
        merged_item=analysis_utils.AnalysisItem(
            yaml_file_contents={
                "AnalysisType": "rule",
                "RuleID": "fake.rule.1",
                "Filename": "fake_rule_1.py",
            },
            yaml_file_path=str(rule_path / "fake_rule_1.yml"),
        ),
    )

    migrate.ensure_python_file_exists(item)
    assert item.merged_item is not None
    assert not (rule_path / "fake_rule_1.py").exists()


#######################################################################################
### Test migration status
#######################################################################################


def test_write_migration_results_empty(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    migrate.MigrationStatus().write_migration_status()

    assert not (tmp_path / MIGRATION_STATUS_FILE_PATH).exists()


def test_write_migration_results_no_conflicts(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    migrate.MigrationStatus(
        items_migrated={
            "fake.rule.1": migrate.MigrationItem(
                analysis_id="fake.rule.1", pretty_analysis_type="Rule"
            ),
            "fake.rule.2": migrate.MigrationItem(
                analysis_id="fake.rule.2", pretty_analysis_type="Rule"
            ),
            "fake.policy.1": migrate.MigrationItem(
                analysis_id="fake.policy.1", pretty_analysis_type="Policy"
            ),
            "fake.policy.2": migrate.MigrationItem(
                analysis_id="fake.policy.2", pretty_analysis_type="Policy"
            ),
        },
    ).write_migration_status()

    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).read_text() == create_migration_status_markdown(
        [
            "(Policy) fake.policy.1",
            "(Policy) fake.policy.2",
            "(Rule) fake.rule.1",
            "(Rule) fake.rule.2",
        ],
        [],
        [],
    )


def test_write_migration_results_with_conflicts_only(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    migrate.MigrationStatus(
        items_with_conflicts={
            "fake.rule.1": migrate.MigrationItem(
                analysis_id="fake.rule.1", pretty_analysis_type="Rule"
            ),
            "fake.rule.2": migrate.MigrationItem(
                analysis_id="fake.rule.2", pretty_analysis_type="Rule"
            ),
            "fake.policy.1": migrate.MigrationItem(
                analysis_id="fake.policy.1", pretty_analysis_type="Policy"
            ),
            "fake.policy.2": migrate.MigrationItem(
                analysis_id="fake.policy.2", pretty_analysis_type="Policy"
            ),
        },
    ).write_migration_status()

    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).exists()
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).read_text() == create_migration_status_markdown(
        [],
        [
            "(Policy) fake.policy.1",
            "(Policy) fake.policy.2",
            "(Rule) fake.rule.1",
            "(Rule) fake.rule.2",
        ],
        [],
    )


def test_write_migration_results(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    migrate.MigrationStatus(
        items_with_conflicts={
            "fake.rule.1": migrate.MigrationItem(
                analysis_id="fake.rule.1", pretty_analysis_type="Rule"
            ),
            "fake.rule.2": migrate.MigrationItem(
                analysis_id="fake.rule.2", pretty_analysis_type="Rule"
            ),
            "fake.policy.1": migrate.MigrationItem(
                analysis_id="fake.policy.1", pretty_analysis_type="Policy"
            ),
            "fake.policy.2": migrate.MigrationItem(
                analysis_id="fake.policy.2", pretty_analysis_type="Policy"
            ),
        },
        items_migrated={
            "fake.rule.1": migrate.MigrationItem(
                analysis_id="fake.rule.1", pretty_analysis_type="Rule"
            ),
            "fake.rule.2": migrate.MigrationItem(
                analysis_id="fake.rule.2", pretty_analysis_type="Rule"
            ),
            "fake.policy.1": migrate.MigrationItem(
                analysis_id="fake.policy.1", pretty_analysis_type="Policy"
            ),
            "fake.policy.2": migrate.MigrationItem(
                analysis_id="fake.policy.2", pretty_analysis_type="Policy"
            ),
        },
        items_deleted={
            "fake.pack.1": migrate.MigrationItem(
                analysis_id="fake.pack.1",
                pretty_analysis_type="Pack",
                reason="Item is dead to me. I deleted it.",
            ),
            "fake.pack.2": migrate.MigrationItem(
                analysis_id="fake.pack.2",
                pretty_analysis_type="Pack",
                reason="Item is dead to me. I deleted it.",
            ),
        },
    ).write_migration_status()

    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).read_text() == create_migration_status_markdown(
        [
            "(Policy) fake.policy.1",
            "(Policy) fake.policy.2",
            "(Rule) fake.rule.1",
            "(Rule) fake.rule.2",
        ],
        [
            "(Policy) fake.policy.1",
            "(Policy) fake.policy.2",
            "(Rule) fake.rule.1",
            "(Rule) fake.rule.2",
        ],
        [
            ("(Pack) fake.pack.1", "Item is dead to me. I deleted it."),
            ("(Pack) fake.pack.2", "Item is dead to me. I deleted it."),
        ],
    )


def test_migration_status_write(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    CACHED_MIGRATION_STATUS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    migration_status = migrate.MigrationStatus(
        items_with_conflicts={
            "fake.rule.1": migrate.MigrationItem(
                analysis_id="fake.rule.1",
                pretty_analysis_type="Rule",
                merged_item=analysis_utils.AnalysisItem(
                    yaml_file_contents={
                        "AnalysisType": "rule",
                        "RuleID": "fake.rule.1",
                    },
                    yaml_file_path=str(tmp_path / "fake_rule_1.yml"),
                ),
            ),
            "fake.policy.1": migrate.MigrationItem(
                analysis_id="fake.policy.1", pretty_analysis_type="Policy"
            ),
        },
        items_migrated={
            "fake.rule.1": migrate.MigrationItem(
                analysis_id="fake.rule.1", pretty_analysis_type="Rule"
            ),
            "fake.policy.1": migrate.MigrationItem(
                analysis_id="fake.policy.1", pretty_analysis_type="Policy"
            ),
        },
        items_deleted={
            "fake.pack.1": migrate.MigrationItem(
                analysis_id="fake.pack.1",
                pretty_analysis_type="Pack",
                reason="Item is dead to me. I deleted it.",
            ),
            "fake.pack.2": migrate.MigrationItem(
                analysis_id="fake.pack.2",
                pretty_analysis_type="Pack",
                reason="Item is dead to me. I deleted it.",
            ),
        },
    )

    expected_json = {
        "items_with_conflicts": {
            "fake.rule.1": {
                "analysis_id": "fake.rule.1",
                "pretty_analysis_type": "Rule",
                "reason": None,
            },
            "fake.policy.1": {
                "analysis_id": "fake.policy.1",
                "pretty_analysis_type": "Policy",
                "reason": None,
            },
        },
        "items_migrated": {
            "fake.rule.1": {
                "analysis_id": "fake.rule.1",
                "pretty_analysis_type": "Rule",
                "reason": None,
            },
            "fake.policy.1": {
                "analysis_id": "fake.policy.1",
                "pretty_analysis_type": "Policy",
                "reason": None,
            },
        },
        "items_deleted": {
            "fake.pack.1": {
                "analysis_id": "fake.pack.1",
                "pretty_analysis_type": "Pack",
                "reason": "Item is dead to me. I deleted it.",
            },
            "fake.pack.2": {
                "analysis_id": "fake.pack.2",
                "pretty_analysis_type": "Pack",
                "reason": "Item is dead to me. I deleted it.",
            },
        },
    }

    migration_status.write_migration_status()
    assert (tmp_path / CACHED_MIGRATION_STATUS_FILE_PATH).exists()
    assert json.loads((tmp_path / CACHED_MIGRATION_STATUS_FILE_PATH).read_text()) == expected_json
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).exists()
    assert (tmp_path / MIGRATION_STATUS_FILE_PATH).read_text() == create_migration_status_markdown(
        [
            "(Policy) fake.policy.1",
            "(Rule) fake.rule.1",
        ],
        [
            "(Policy) fake.policy.1",
            "(Rule) fake.rule.1",
        ],
        [
            ("(Pack) fake.pack.1", "Item is dead to me. I deleted it."),
            ("(Pack) fake.pack.2", "Item is dead to me. I deleted it."),
        ],
    )


def test_migration_status_load_empty(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    migration_status = migrate.MigrationStatus.load_migration_status()
    assert migration_status.items_with_conflicts == {}
    assert migration_status.items_migrated == {}
    assert migration_status.items_deleted == {}


def test_migration_status_load_not_empty(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    status_json = {
        "items_with_conflicts": {
            "fake.rule.1": {
                "analysis_id": "fake.rule.1",
                "pretty_analysis_type": "Rule",
            },
            "fake.rule.2": {
                "analysis_id": "fake.rule.2",
                "pretty_analysis_type": "Rule",
            },
        },
        "items_migrated": {
            "fake.rule.1": {
                "analysis_id": "fake.rule.1",
                "pretty_analysis_type": "Rule",
            },
            "fake.rule.2": {
                "analysis_id": "fake.rule.2",
                "pretty_analysis_type": "Rule",
            },
        },
        "items_deleted": {
            "fake.pack.1": {
                "analysis_id": "fake.pack.1",
                "pretty_analysis_type": "Pack",
                "reason": "Item is dead to me. I deleted it.",
            },
            "fake.pack.2": {
                "analysis_id": "fake.pack.2",
                "pretty_analysis_type": "Pack",
                "reason": "Item is dead to me. I deleted it.",
            },
        },
    }

    CACHED_MIGRATION_STATUS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHED_MIGRATION_STATUS_FILE_PATH.write_text(json.dumps(status_json))

    migration_status = migrate.MigrationStatus.load_migration_status()
    assert migration_status.items_with_conflicts == {
        "fake.rule.1": migrate.MigrationItem(
            analysis_id="fake.rule.1", pretty_analysis_type="Rule"
        ),
        "fake.rule.2": migrate.MigrationItem(
            analysis_id="fake.rule.2", pretty_analysis_type="Rule"
        ),
    }
    assert migration_status.items_migrated == {
        "fake.rule.1": migrate.MigrationItem(
            analysis_id="fake.rule.1", pretty_analysis_type="Rule"
        ),
        "fake.rule.2": migrate.MigrationItem(
            analysis_id="fake.rule.2", pretty_analysis_type="Rule"
        ),
    }
    assert migration_status.items_deleted == {
        "fake.pack.1": migrate.MigrationItem(
            analysis_id="fake.pack.1",
            pretty_analysis_type="Pack",
            reason="Item is dead to me. I deleted it.",
        ),
        "fake.pack.2": migrate.MigrationItem(
            analysis_id="fake.pack.2",
            pretty_analysis_type="Pack",
            reason="Item is dead to me. I deleted it.",
        ),
    }
