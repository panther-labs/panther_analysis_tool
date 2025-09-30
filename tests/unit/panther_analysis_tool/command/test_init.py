import os
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from panther_analysis_tool.command import init_project


class TestInitProject(unittest.TestCase):
    def check_gitignore_content(self, gitignore_content: str) -> None:
        self.assertEqual(gitignore_content.count(".vscode/"), 1, gitignore_content)
        self.assertEqual(gitignore_content.count(".idea/"), 1, gitignore_content)
        self.assertEqual(gitignore_content.count(".cache"), 1, gitignore_content)
        self.assertEqual(gitignore_content.count(".panther_settings.*"), 1, gitignore_content)
        self.assertEqual(gitignore_content.count("__pycache__/"), 1, gitignore_content)
        self.assertEqual(gitignore_content.count("*.pyc"), 1, gitignore_content)
        self.assertEqual(gitignore_content.count("panther-analysis-*.zip"), 1, gitignore_content)

    def test_init_project_with_no_gitignore(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch("sys.stdout", new=StringIO()) as mock_stdout:
            init_project.run(temp_dir)
            self.assertTrue(os.path.exists(Path(temp_dir) / ".gitignore"))
            self.assertIn(".gitignore file created", mock_stdout.getvalue())
            self.assertIn("Project is ready to use!", mock_stdout.getvalue())

            gitignore_content = (Path(temp_dir) / ".gitignore").read_text()
            self.check_gitignore_content(gitignore_content)

    def test_init_project_with_gitignore(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch("sys.stdout", new=StringIO()) as mock_stdout:
            gitignore_path = Path(temp_dir) / ".gitignore"
            gitignore_path.touch()
            gitignore_path.write_text("# something aleady here\n./stuff\n.vscode/\nstuff")
            
            init_project.run(temp_dir)
            self.assertTrue(os.path.exists(gitignore_path))
            self.assertNotIn(".gitignore file created", mock_stdout.getvalue())
            self.assertIn("Project is ready to use!", mock_stdout.getvalue())

            gitignore_content = gitignore_path.read_text()
            self.assertIn("# something aleady here\n./stuff\n.vscode", gitignore_content)
            self.check_gitignore_content(gitignore_content)
