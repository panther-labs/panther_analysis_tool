# This file was generated in whole or in part by GitHub Copilot.

import json
from unittest import TestCase, mock

from panther_analysis_tool.analysis_utils import (
    ClassifiedAnalysis,
    ClassifiedAnalysisContainer,
    get_simple_detections_as_python,
    load_analysis_specs,
    transpile_inline_filters,
)
from panther_analysis_tool.backend.client import (
    BackendError,
    BackendResponse,
    TranspileFiltersResponse,
    TranspileToPythonResponse,
)
from panther_analysis_tool.backend.mocks import MockBackend
from panther_analysis_tool.constants import BACKEND_FILTERS_ANALYSIS_SPEC_KEY
from tests.unit.panther_analysis_tool.test_main import DETECTIONS_FIXTURES_PATH


class TestGetSimpleDetectionsAsPython(TestCase):
    def get_specs_for_test(self):
        specs = []
        for i in range(10):
            specs.append(
                ClassifiedAnalysis(
                    f"filname-{i}",
                    f"filepath-{i}",
                    {
                        "Detection": [
                            {
                                "Key": "event_type",
                                "Condition": "Equals",
                                "Value": f"team_privacy_settings_changed-{i}",
                            },
                            {
                                "DeepKey": ["details", "new_value"],
                                "Condition": "Equals",
                                "Value": f"public-{i}",
                            },
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
            self.assertEqual(actual.analysis_spec["body"], "def rule(event): return True")


class TestTranspileInlineFilters(TestCase):
    def get_specs_for_test(self) -> ClassifiedAnalysisContainer:
        specs = ClassifiedAnalysisContainer()
        for i in range(2):
            specs.simple_detections.append(
                ClassifiedAnalysis(
                    f"filname-{i}",
                    f"filepath-{i}",
                    {
                        "InlineFilters": [
                            {
                                "PathSpecifier": "event_type",
                                "Condition": "Equals",
                                "Value": "team_privacy_settings_changed",
                            }
                        ],
                        "Detection": [
                            {
                                "Key": "event_type",
                                "Condition": "Equals",
                                "Value": "team_privacy_settings_changed",
                            },
                        ],
                    },
                )
            )
            specs.simple_detections.append(
                ClassifiedAnalysis(
                    f"filname-{i}",
                    f"filepath-{i}",
                    {
                        "Detection": [
                            {
                                "Key": "event_type",
                                "Condition": "Equals",
                                "Value": "team_privacy_settings_changed",
                            },
                        ]
                    },
                )
            )
            specs.detections.append(
                ClassifiedAnalysis(
                    f"filname-{i}",
                    f"filepath-{i}",
                    {
                        "InlineFilters": [
                            {
                                "PathSpecifier": "event_type",
                                "Condition": "Equals",
                                "Value": "team_privacy_settings_changed",
                            }
                        ],
                        "Filename": "python.py",
                    },
                )
            )
            specs.detections.append(
                ClassifiedAnalysis(
                    f"filname-{i}",
                    f"filepath-{i}",
                    {"Filename": "python.py"},
                )
            )
        return specs

    def get_transpiled_filter(self) -> str:
        return json.dumps(
            {
                "statement": {
                    "target": "event_type",
                    "operator": "Equals",
                    "value": "team_privacy_settings_changed",
                }
            }
        )

    def test_happy_path(self) -> None:
        specs = self.get_specs_for_test()
        filters = self.get_transpiled_filter()
        backend = MockBackend()
        backend.transpile_filters = mock.MagicMock(
            return_value=BackendResponse(
                data=TranspileFiltersResponse(
                    transpiled_filters=[
                        filters
                        for d in specs.detections + specs.simple_detections
                        if "InlineFilters" in d.analysis_spec
                    ],
                ),
                status_code=200,
            )
        )
        transpile_inline_filters(specs, backend)

        for actual in specs.detections + specs.simple_detections:
            if "InlineFilters" in actual.analysis_spec:
                self.assertEqual(
                    json.loads(filters), actual.analysis_spec.get(BACKEND_FILTERS_ANALYSIS_SPEC_KEY)
                )
            else:
                self.assertEqual(None, actual.analysis_spec.get(BACKEND_FILTERS_ANALYSIS_SPEC_KEY))

    def test_no_filters(self) -> None:
        import logging

        specs = ClassifiedAnalysisContainer()
        backend = MockBackend()
        specs.simple_detections = [
            ClassifiedAnalysis(
                "filname",
                "filepath",
                {
                    "Detection": [
                        {
                            "Key": "event_type",
                            "Condition": "Equals",
                            "Value": "team_privacy_settings_changed",
                        },
                    ]
                },
            )
        ]
        specs.detections = [ClassifiedAnalysis("filname", "filepath", {"Filename": "python.py"})]
        with mock.patch.multiple(
            logging, debug=mock.DEFAULT, warning=mock.DEFAULT, info=mock.DEFAULT
        ) as logging_mocks:
            transpile_inline_filters(specs, backend)
            self.assertEqual(logging_mocks["warning"].call_count, 0)


class TestMiscUtils(TestCase):
    def test_ignored_files_are_not_loaded(self):
        for spec_filename, _, _, _ in load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH], ignore_files=["./example_ignored.yml"]
        ):
            self.assertTrue(spec_filename != "example_ignored.yml")

    def test_multiple_ignored_files_are_not_loaded(self):
        for spec_filename, _, _, _ in load_analysis_specs(
            [DETECTIONS_FIXTURES_PATH],
            ignore_files=["./example_ignored.yml", "./example_ignored_multi.yml"],
        ):
            self.assertTrue(
                spec_filename != "example_ignored.yml"
                and spec_filename != "example_ignored_multi.yml"
            )
