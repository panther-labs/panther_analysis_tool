import pathlib
from unittest.mock import call

from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture

from panther_analysis_tool.command import pull
from panther_analysis_tool.constants import (
    CACHE_DIR,
    CACHED_VERSIONS_FILE_PATH,
    PANTHER_ANALYSIS_SQLITE_FILE_PATH,
)
from panther_analysis_tool.core import analysis_cache, yaml

_FAKE_PY = """
def rule(event):
    return True
"""

_FAKE_RULE_1_V1 = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_rule_1.py",
        "RuleID": "fake.rule.1",
        "Enabled": True,
        "Description": "Fake rule 1 v1",
    }
)

_FAKE_RULE_2_V1 = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_rule_2.py",
        "RuleID": "fake.rule.2",
        "Enabled": True,
        "Description": "Fake rule 2 v1",
    }
)

_FAKE_RULE_2_V2 = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_rule_2.py",
        "RuleID": "fake.rule.2",
        "Enabled": True,
        "Description": "Fake rule 2 v2",
        "NewField": "fake_rule_2_v2",
    }
)

_FAKE_USER_RULE_2_V1 = yaml.dump(
    {
        "AnalysisType": "rule",
        "Filename": "fake_user_rule_2.py",
        "RuleID": "fake.rule.2",  # matches _FAKE_RULE_2_V2
        "Enabled": True,
        "Description": "Fake user rule 2 v1",
        "BaseVersion": 1,
    }
)

_FAKE_VERSIONS_FILE = yaml.dump(
    {
        "versions": {
            "fake.rule.1": {
                "version": 1,
                "type": "rule",
                "sha256": "fake_sha256_1",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_1",
                        "yaml_file_path": "fake_rule_1.yaml",
                        "py_file_path": "fake_rule_1.py",
                    },
                },
            },
            "fake.rule.2": {
                "version": 2,
                "type": "rule",
                "sha256": "fake_sha256_2",
                "history": {
                    "1": {
                        "version": 1,
                        "commit_hash": "fake_commit_hash_2_1",
                        "yaml_file_path": "fake_rule_2.yaml",
                        "py_file_path": "fake_rule_2.py",
                    },
                    "2": {
                        "version": 2,
                        "commit_hash": "fake_commit_hash_2_2",
                        "yaml_file_path": "fake_rule_2.yaml",
                        "py_file_path": "fake_rule_2.py",
                    },
                },
            },
        },
    }
)


def set_up_cache(tmp_path: pathlib.Path, monkeypatch: MonkeyPatch) -> analysis_cache.AnalysisCache:
    monkeypatch.chdir(tmp_path)
    pa_clone_path = CACHE_DIR / "panther-analysis"
    pa_clone_path.mkdir(parents=True, exist_ok=True)

    PANTHER_ANALYSIS_SQLITE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANTHER_ANALYSIS_SQLITE_FILE_PATH.touch()

    # fake cloning panther-analysis repository
    create_file_with_text(pa_clone_path / "rules" / "fake_rule_1.yaml", _FAKE_RULE_1_V1)
    create_file_with_text(pa_clone_path / "rules" / "fake_rule_1.py", _FAKE_PY)
    create_file_with_text(pa_clone_path / "rules" / "fake_rule_2.yaml", _FAKE_RULE_2_V2)
    create_file_with_text(pa_clone_path / "rules" / "fake_rule_2.py", _FAKE_PY)
    create_file_with_text(CACHED_VERSIONS_FILE_PATH, _FAKE_VERSIONS_FILE)

    # fake user's analysis items
    pathlib.Path("rules").mkdir(parents=True, exist_ok=True)
    create_file_with_text(pathlib.Path("rules") / "fake_user_rule_2.yaml", _FAKE_USER_RULE_2_V1)
    create_file_with_text(pathlib.Path("rules") / "fake_user_rule_2.py", _FAKE_PY)

    cache = analysis_cache.AnalysisCache()
    cache.create_tables()
    return cache


def create_file_with_text(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    path.write_text(text)


def _setup_pull_test(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """Common setup for pull tests."""
    mocker.patch(
        "panther_analysis_tool.command.pull.analysis_cache.git_helpers.panther_analysis_latest_release_commit",
        return_value="fake_commit_hash_1",
    )
    mocker.patch(
        "panther_analysis_tool.command.pull.analysis_cache._clone_panther_analysis",
        return_value=None,
    )
    mocker.patch("panther_analysis_tool.command.pull.git_helpers.chdir_to_git_root")
    set_up_cache(tmp_path, monkeypatch)


def test_pull_and_merge_with_conflicts(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """Test pull when merge has conflicts."""
    mock_print = mocker.patch("panther_analysis_tool.command.merge.print")
    _setup_pull_test(tmp_path, monkeypatch, mocker)

    pull.run(pull.PullArgs())

    mock_print.assert_has_calls(
        [
            call(
                "1 merge conflict(s) found, run `EDITOR=<editor> pat merge <id>` to resolve each conflict:"
            ),
            call("  * fake.rule.2"),
        ]
    )


def test_pull_no_mergeable_items(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """Test pull when there are no mergeable items (everything is up to date)."""
    mock_print = mocker.patch("panther_analysis_tool.command.merge.print")
    mock_clone_deps = mocker.patch("panther_analysis_tool.command.pull.clone_item.clone_deps")
    _setup_pull_test(tmp_path, monkeypatch, mocker)

    # Create a user rule that's already at the latest version
    _FAKE_USER_RULE_2_V2 = yaml.dump(
        {
            "AnalysisType": "rule",
            "Filename": "fake_user_rule_2.py",
            "RuleID": "fake.rule.2",
            "Enabled": True,
            "Description": "Fake user rule 2 v2",
            "BaseVersion": 2,  # Already at latest version
        }
    )
    pathlib.Path("rules").mkdir(parents=True, exist_ok=True)
    create_file_with_text(pathlib.Path("rules") / "fake_user_rule_2.yaml", _FAKE_USER_RULE_2_V2)
    create_file_with_text(pathlib.Path("rules") / "fake_user_rule_2.py", _FAKE_PY)

    pull.run(pull.PullArgs())

    # Should not print anything about merging
    mock_print.assert_not_called()
    # Should still try to clone deps (but with empty list)
    mock_clone_deps.assert_called_once_with([])


def test_pull_preview_mode(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """Test pull in preview mode shows what would be updated without actually updating."""
    mock_print = mocker.patch("panther_analysis_tool.command.merge.print")
    mock_clone_deps = mocker.patch("panther_analysis_tool.command.pull.clone_item.clone_deps")
    _setup_pull_test(tmp_path, monkeypatch, mocker)

    pull.run(pull.PullArgs(preview=True))

    # Preview mode should show conflicts
    mock_print.assert_has_calls(
        [
            call(
                "1 analysis item(s) will have merge conflicts when updated to latest Panther version:"
            ),
            call("  * fake.rule.2"),
        ]
    )
    # Should not clone dependencies in preview mode (no merged items)
    mock_clone_deps.assert_called_once_with([])


def test_pull_clones_dependencies(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    """Test that pull clones dependencies from successfully merged items."""
    mock_clone_deps = mocker.patch("panther_analysis_tool.command.pull.clone_item.clone_deps")
    _setup_pull_test(tmp_path, monkeypatch, mocker)

    pull.run(pull.PullArgs())

    # Verify clone_deps is always called (with merged items, or empty list if conflicts)
    mock_clone_deps.assert_called_once()
    assert isinstance(mock_clone_deps.call_args[0][0], list)
