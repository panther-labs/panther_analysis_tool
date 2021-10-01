"""
Panther Analysis Tool is a command line interface for writing,
testing, and packaging policies/rules.
Copyright (C) 2020 Panther Labs Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from collections.abc import Mapping
from typing import List

from panther_analysis_tool.rule import Detection

TYPE_POLICY = "POLICY"


class Policy(Detection):
    """Panther policy metadata and imported module."""

    # default detection types for policies
    default_detection_type = TYPE_POLICY

    # policies have a rule method
    matcher_function_name = "policy"

    # a policy should trigger an alert on False return value
    matcher_alert_value = False

    # suppressions for the policy
    suppressions: List[str] = []

    def matcher_function(self, event: Mapping) -> bool:
        command = getattr(self._module, self.matcher_function_name)
        return self._run_command(command, event, bool)
