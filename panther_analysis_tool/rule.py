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

import logging
from collections.abc import Mapping

from panther_analysis_tool.detection import (
    Detection,
    DetectionResult,
    TYPE_RULE,
)
from panther_analysis_tool.enriched_event import PantherEvent


# Temporary alias for compatibility
get_logger = logging.getLogger

class Rule(Detection):
    """Panther rule metadata and imported module."""

    # pylint: disable=too-many-branches,too-many-statements
    def __init__(self, config: Mapping):
        """Create new rule from a dict.

        Args:
            config: Dictionary that we expect to have the following keys:
                analysisType: either RULE or SCHEDULED_RULE
                id: Unique rule identifier
                body: The rule body
                versionId: The version of the rule
                (Optional) path: The rule module path
                (Optional) dedupPeriodMinutes: The period during which
                the events will be deduplicated
        """
        # initialize core parameters
        super().__init__(config, TYPE_RULE)


    def run(
        self, event: PantherEvent, outputs: dict, outputs_names: dict, batch_mode: bool = True
    ) -> DetectionResult:
        return super().run(event, outputs, outputs_names, batch_mode)
