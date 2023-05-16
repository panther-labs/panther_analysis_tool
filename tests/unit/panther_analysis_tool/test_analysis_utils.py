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
# This file was generated in whole or in part by GitHub Copilot.

from unittest import mock, TestCase

from panther_analysis_tool.analysis_utils import get_simple_detections_as_python
from panther_analysis_tool.backend.client import BackendResponse, BackendError, TranspileToPythonResponse
from panther_analysis_tool.backend.mocks import MockBackend


class TestAnalysisUtils(TestCase):

    def get_specs_for_test(self):
        specs = []
        for i in range(10):
            specs.append(
                (
                    f"filname-{i}",
                    f"filepath-{i}",
                    {
                        "Detection": [
                            {
                                "Key": "event_type",
                                "Condition": "Equals",
                                "Value": f"team_privacy_settings_changed-{i}"
                            },
                            {
                                "DeepKey": ["details", "new_value"],
                                "Condition": "Equals",
                                "Value": f"public-{i}"
                            }
                        ]
                    },
                )
            )
        return specs

    def test_no_backend(self) -> None:
        specs = self.get_specs_for_test()
        self.assertEqual(get_simple_detections_as_python(specs), specs)

    def test_backend_error(self) -> None:
        specs = self.get_specs_for_test()
        backend = MockBackend()
        backend.transpile_simple_detection_to_python = mock.MagicMock(
            side_effect=BackendError("that won't transpile!")
        )
        self.assertEqual(get_simple_detections_as_python(specs, backend), specs)

    def test_base_error(self) -> None:
        specs = self.get_specs_for_test()
        backend = MockBackend()
        backend.transpile_simple_detection_to_python = mock.MagicMock(
            side_effect=BaseException("uh-oh")
        )
        self.assertEqual(get_simple_detections_as_python(specs, backend), specs)

    def test_happy_path(self) -> None:
        specs = self.get_specs_for_test()
        backend = MockBackend()
        backend.transpile_simple_detection_to_python = mock.MagicMock(
            return_value=BackendResponse(
                data=TranspileToPythonResponse(
                    transpiled_python=["def rule(event): return True" for _ in range(len(specs))],
                ),
                status_code=200,
            )
        )
        output = get_simple_detections_as_python(specs, backend)
        for actual in output:
            self.assertEqual(actual[2]["body"], "def rule(event): return True")
