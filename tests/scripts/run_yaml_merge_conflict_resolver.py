"""
Run the YAML conflict resolver GUI with the yaml_merge_conflict fixtures.

Usage:
    python tests/scripts/run_yaml_merge_conflict_resolver.py
"""

import pathlib

from panther_analysis_tool.gui import yaml_conflict_resolver_gui

conflict_files_path = pathlib.Path(__file__).parent.parent / "fixtures" / "yaml_merge_conflict"
base_yaml_path = conflict_files_path / "base_yaml.yml"
customer_yaml_path = conflict_files_path / "customer_yaml.yml"
panther_yaml_path = conflict_files_path / "panther_yaml.yml"

if __name__ == "__main__":
    app = yaml_conflict_resolver_gui.YAMLConflictResolverApp(
        customer_python="def rule(event):\n    return True\n",
        raw_customer_yaml=customer_yaml_path.read_text(),
        raw_panther_yaml=panther_yaml_path.read_text(),
        raw_base_yaml=base_yaml_path.read_text(),
    )
    app.run()
