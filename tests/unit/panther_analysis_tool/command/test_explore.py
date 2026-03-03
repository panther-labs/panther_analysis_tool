"""Unit tests for the explore command."""

import pathlib

import pytest
from _pytest.monkeypatch import MonkeyPatch

from panther_analysis_tool.command import explore
from panther_analysis_tool.core import versions_file

from .test_install import _FAKE_PY, _STALE_RULE_V1, insert_spec, set_up_cache


def test_load_panther_analysis_specs_skips_specs_missing_from_versions(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
    """Specs that exist in the cache but not in the versions file are skipped (no KeyError)."""
    monkeypatch.setattr(versions_file, "_VERSIONS", None)
    cache = set_up_cache(tmp_path, monkeypatch)
    insert_spec(cache, _STALE_RULE_V1, 1, "RuleID", "stale.rule.1", _FAKE_PY)
    specs = explore.load_panther_analysis_specs(show_progress_bar=False)
    assert len(specs) == 15
    ids = [item.analysis_id() for item in specs]
    assert "stale.rule.1" not in ids
