import os
import subprocess
import tempfile
import unittest
from unittest import mock

from panther_analysis_tool.core import git_helpers


class TestGitHelpers(unittest.TestCase):
    def test_panther_analysis_release_url(self) -> None:
        self.assertEqual(
            git_helpers.panther_analysis_release_url(),
            "https://api.github.com/repos/panther-labs/panther-analysis/releases/latest",
        )

    def test_panther_analysis_latest_release_commit(self) -> None:
        with mock.patch(
            "requests.get", return_value=mock.Mock(json=lambda: {"tag_name": "v7.7.7"})
        ):
            self.assertRegex(
                git_helpers.panther_analysis_latest_release_commit(),
                "v7.7.7",
            )

    def test_clone_panther_analysis(self) -> None:
        with (
            mock.patch("shutil.rmtree", return_value=None),
            mock.patch("os.chdir", return_value=None),
            mock.patch(
                "subprocess.run", return_value=subprocess.CompletedProcess(returncode=0, args=[])
            ) as mock_subprocess_run,
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            os.chdir(temp_dir)

            git_helpers.clone_panther_analysis("main")
            self.assertEqual(mock_subprocess_run.call_count, 1)

    def test_clone_panther_analysis_with_commit(self) -> None:
        with (
            mock.patch("shutil.rmtree", return_value=None),
            mock.patch("os.chdir", return_value=None),
            mock.patch(
                "subprocess.run", return_value=subprocess.CompletedProcess(returncode=0, args=[])
            ) as mock_subprocess_run,
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            os.chdir(temp_dir)

            git_helpers.clone_panther_analysis("main", "v7.7.7")
            self.assertEqual(mock_subprocess_run.call_count, 2)

    def test_clone_panther_analysis_subproccess_fails(self) -> None:
        with (
            mock.patch("shutil.rmtree", return_value=None),
            mock.patch("os.chdir", return_value=None),
            mock.patch(
                "subprocess.run", return_value=subprocess.CompletedProcess(returncode=1, args=[])
            ),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            os.chdir(temp_dir)

            with self.assertRaises(RuntimeError):
                git_helpers.clone_panther_analysis("main", "v7.7.7")

    def test_get_panther_analysis_file_contents(self) -> None:
        with mock.patch("requests.get", return_value=mock.Mock(text="stuff")):
            result = git_helpers.get_panther_analysis_file_contents(
                "f40e2829304b30eacdb51f6d9023c89fa8f19b58",
                "rules/atlassian_rules/user_logged_in_as_user.yml",
            )
            self.assertEqual(result, "stuff")
