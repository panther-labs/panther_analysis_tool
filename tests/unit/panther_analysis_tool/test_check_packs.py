import os
import unittest
from pathlib import Path

from panther_analysis_tool.main import check_packs

FIXTURES_PATH = Path(__file__).parents[2] / "fixtures/check-packs"


class TestCheckPacks(unittest.TestCase):
    _bad_packs: dict = None

    def get_bad_packs(self) -> dict:
        if self._bad_packs is not None:
            return self._bad_packs

        path = FIXTURES_PATH / "missing-dependencies"
        exit_code, res = check_packs(path)

        assert exit_code == 1
        res = res.split("\n")
        self._bad_packs = {}
        current_key = ""
        for line in res[1:]:
            if line.startswith(" ") or not line:
                continue
            if line.startswith("\t"):
                self._bad_packs[current_key].append(line.strip())
                continue
            current_key = Path(line.strip()).name
            self._bad_packs[current_key] = []

        return self._bad_packs

    def test_fixtures(self) -> None:
        path = FIXTURES_PATH / "packless-rule"
        exit_code, res = check_packs(path)

        assert exit_code == 1
        assert "Test.Missing" in res

    def test_missing_global(self) -> None:
        bad_packs = self.get_bad_packs()
        assert "missing_global.yml" in bad_packs
        missing_items = bad_packs["missing_global.yml"]
        assert "a_helper" in missing_items

    def test_missing_data_model(self) -> None:
        bad_packs = self.get_bad_packs()
        assert "missing_datamodel.yml" in bad_packs
        missing_items = bad_packs["missing_datamodel.yml"]
        assert "panther" in missing_items
        assert "Standard.AWS.CloudTrail" in missing_items

    def test_missing_query(self) -> None:
        bad_packs = self.get_bad_packs()
        assert "missing_query.yml" in bad_packs
        missing_items = bad_packs["missing_query.yml"]
        assert "A Test Query" in missing_items

    def test_missing_subrules(self) -> None:
        bad_packs = self.get_bad_packs()
        assert "missing_subrules.yml" in bad_packs
        missing_items = bad_packs["missing_subrules.yml"]
        assert "AWS.CloudTrail.IaaS" in missing_items
        assert "GitHub.CICD" in missing_items

    def test_empty_dir(self) -> None:
        current_dir = os.path.dirname(os.path.realpath(__file__))
        print(current_dir)
        exit_code, res = check_packs(current_dir)

        assert exit_code == 0
        assert res == "Looks like packs are up to date"

    def test_experimental_in_pack(self) -> None:
        # Consolidated test: experimental items should not be allowed in packs
        path = FIXTURES_PATH / "consolidated"
        # Temporarily rename the with_experimental pack to be the only pack
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            # Copy rules
            shutil.copytree(path / "rules", Path(tmpdir) / "rules")
            # Copy only the experimental pack
            (Path(tmpdir) / "packs").mkdir()
            shutil.copy(path / "packs/with_experimental.yml", Path(tmpdir) / "packs/")

            exit_code, res = check_packs(tmpdir)

            assert exit_code == 1
            assert "experimental items are not allowed in packs" in res
            assert "Test.Experimental.Rule" in res
            # Test case-insensitivity: Status: Experimental should also be caught
            assert "Test.Experimental.Rule.Uppercase" in res

    def test_experimental_not_in_pack_is_ok(self) -> None:
        # Consolidated test: experimental items not in packs should not be flagged as missing
        path = FIXTURES_PATH / "consolidated"
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            # Copy rules
            shutil.copytree(path / "rules", Path(tmpdir) / "rules")
            # Copy only the valid pack (excludes experimental)
            (Path(tmpdir) / "packs").mkdir()
            shutil.copy(path / "packs/valid.yml", Path(tmpdir) / "packs/")

            exit_code, res = check_packs(tmpdir)

            assert exit_code == 0
            assert res == "Looks like packs are up to date"

    def test_deprecated_displayname_in_pack(self) -> None:
        # Consolidated test: items with DEPRECATED in DisplayName should not be allowed in packs
        path = FIXTURES_PATH / "consolidated"
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "rules").mkdir()
            (Path(tmpdir) / "packs").mkdir()
            # Copy only the deprecated displayname rule
            for ext in [".yml", ".py"]:
                shutil.copy(path / f"rules/deprecated_displayname{ext}", Path(tmpdir) / "rules/")
            shutil.copy(path / "packs/with_deprecated_displayname.yml", Path(tmpdir) / "packs/")

            exit_code, res = check_packs(tmpdir)

            assert exit_code == 1
            assert "deprecated items are not allowed in packs" in res
            assert "Test.Deprecated.DisplayName.Rule" in res

    def test_deprecated_status_in_pack(self) -> None:
        # Consolidated test: items with Status: deprecated should not be allowed in packs
        path = FIXTURES_PATH / "consolidated"
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "rules").mkdir()
            (Path(tmpdir) / "packs").mkdir()
            # Copy only the deprecated status rule
            for ext in [".yml", ".py"]:
                shutil.copy(path / f"rules/deprecated_status{ext}", Path(tmpdir) / "rules/")
            shutil.copy(path / "packs/with_deprecated_status.yml", Path(tmpdir) / "packs/")

            exit_code, res = check_packs(tmpdir)

            assert exit_code == 1
            assert "deprecated items are not allowed in packs" in res
            assert "Test.Deprecated.Status.Rule" in res

    def test_excluded_tags_in_pack(self) -> None:
        # Consolidated test: items with excluded tags should not be allowed in packs
        path = FIXTURES_PATH / "consolidated"
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "rules").mkdir()
            (Path(tmpdir) / "packs").mkdir()
            # Copy only the excluded tag rule
            for ext in [".yml", ".py"]:
                shutil.copy(path / f"rules/excluded_tag{ext}", Path(tmpdir) / "rules/")
            shutil.copy(path / "packs/with_excluded_tag.yml", Path(tmpdir) / "packs/")

            exit_code, res = check_packs(tmpdir)

            assert exit_code == 1
            assert "excluded tags are not allowed in packs" in res
            assert "Test.ExcludedTag.Rule" in res
            assert "no pack" in res
