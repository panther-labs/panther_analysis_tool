import argparse
import datetime
import unittest
from unittest import mock

import dateutil.parser

from panther_analysis_tool.analysis_utils import ClassifiedAnalysis
from panther_analysis_tool.backend.client import (
    BackendResponse,
    MetricsResponse,
    SeriesWithBreakdown,
)
from panther_analysis_tool.backend.mocks import MockBackend
from panther_analysis_tool.command.benchmark import (
    validate_hour,
    validate_log_type,
    validate_rule_count,
)
from panther_analysis_tool.constants import AnalysisTypes


class TestBenchmark(unittest.TestCase):
    def test_validate_rule_count_happy_path(self) -> None:
        analyses = [
            ClassifiedAnalysis(
                file_name="fake_file.yml",
                dir_name="fake_dir",
                analysis_spec={"AnalysisType": AnalysisTypes.RULE},
            )
        ]
        ret = validate_rule_count(analyses)
        self.assertIsInstance(ret, ClassifiedAnalysis)
        self.assertEqual(analyses[0], ret)

    def test_validate_rule_count_too_few_analyses(self) -> None:
        analyses = []
        ret = validate_rule_count(analyses)
        self.assertIsInstance(ret, str)
        self.assertIn("0", ret)

    def test_validate_rule_count_too_many_analyses(self) -> None:
        analyses = [
            ClassifiedAnalysis(
                file_name="fake_file1.yml",
                dir_name="fake_dir",
                analysis_spec={"AnalysisType": AnalysisTypes.RULE},
            ),
            ClassifiedAnalysis(
                file_name="fake_file2.yml",
                dir_name="fake_dir",
                analysis_spec={"AnalysisType": AnalysisTypes.RULE},
            ),
        ]
        ret = validate_rule_count(analyses)
        self.assertIsInstance(ret, str)
        self.assertIn("2", ret)

    def test_validate_rule_count_wrong_type(self) -> None:
        analyses = [
            ClassifiedAnalysis(
                file_name="fake_file.yml",
                dir_name="fake_dir",
                analysis_spec={"AnalysisType": AnalysisTypes.POLICY},
            )
        ]
        ret = validate_rule_count(analyses)
        self.assertIsInstance(ret, str)
        self.assertIn(AnalysisTypes.POLICY, ret)

    def test_validate_log_type_happy_path_provided_match_only(self) -> None:
        log_type = "foo"
        args = argparse.Namespace(log_type=log_type)
        rule = ClassifiedAnalysis(
            file_name="fake_file.yml",
            dir_name="fake_dir",
            analysis_spec={"AnalysisType": AnalysisTypes.RULE, "LogTypes": [log_type]},
        )
        log_type_ret, err = validate_log_type(args, rule)
        self.assertEqual(log_type, log_type_ret)
        self.assertIsNone(err)

    def test_validate_log_type_happy_path_provided_match_one(self) -> None:
        log_type = "foo"
        args = argparse.Namespace(log_type=log_type)
        rule = ClassifiedAnalysis(
            file_name="fake_file.yml",
            dir_name="fake_dir",
            analysis_spec={
                "AnalysisType": AnalysisTypes.RULE,
                "LogTypes": [log_type, "other.log.type"],
            },
        )
        log_type_ret, err = validate_log_type(args, rule)
        self.assertEqual(log_type, log_type_ret)
        self.assertIsNone(err)

    def test_validate_log_type_happy_path_default(self) -> None:
        log_type = "foo"
        args = argparse.Namespace()
        rule = ClassifiedAnalysis(
            file_name="fake_file.yml",
            dir_name="fake_dir",
            analysis_spec={"AnalysisType": AnalysisTypes.RULE, "LogTypes": [log_type]},
        )
        log_type_ret, err = validate_log_type(args, rule)
        self.assertEqual(log_type, log_type_ret)
        self.assertIsNone(err)

    def test_validate_log_type_multiple_none_provided(self) -> None:
        log_type = "foo"
        args = argparse.Namespace()
        rule = ClassifiedAnalysis(
            file_name="fake_file.yml",
            dir_name="fake_dir",
            analysis_spec={
                "AnalysisType": AnalysisTypes.RULE,
                "LogTypes": [log_type, "other.log.type"],
            },
        )
        log_type_ret, err = validate_log_type(args, rule)
        self.assertIsNotNone(err)
        self.assertIsNone(log_type_ret)

    def test_validate_log_type_mismatch(self) -> None:
        log_type = "foo"
        args = argparse.Namespace(log_type=log_type)
        rule = ClassifiedAnalysis(
            file_name="fake_file.yml",
            dir_name="fake_dir",
            analysis_spec={"AnalysisType": AnalysisTypes.RULE, "LogTypes": ["other.log.type"]},
        )
        log_type_ret, err = validate_log_type(args, rule)
        self.assertIsNotNone(err)

    def test_validate_log_type_none_on_rule(self) -> None:
        log_type = "foo"
        args = argparse.Namespace(log_type=log_type)
        rule = ClassifiedAnalysis(
            file_name="fake_file.yml",
            dir_name="fake_dir",
            analysis_spec={"AnalysisType": AnalysisTypes.RULE},
        )
        log_type_ret, err = validate_log_type(args, rule)
        self.assertIsNotNone(err)

    def test_validate_hour_happy_path_provided(self) -> None:
        hour = datetime.datetime.now().astimezone().replace(
            minute=0, second=0, microsecond=0
        ) - datetime.timedelta(days=2)
        args = argparse.Namespace(hour=hour)
        log_type = "foo"
        backend = MockBackend()
        backend.get_metrics = mock.MagicMock(
            return_value=BackendResponse(
                data=MetricsResponse(
                    bytes_processed_per_source=[
                        SeriesWithBreakdown(
                            breakdown={hour.isoformat(): 100}, label=log_type, value=150
                        )
                    ]
                ),
                status_code=200,
            )
        )
        ret = validate_hour(args, log_type, backend)
        self.assertIsInstance(ret, datetime.datetime)
        self.assertEqual(hour, ret)

    def test_validate_hour_happy_path_default(self) -> None:
        hour = datetime.datetime.now().astimezone().replace(
            minute=0, second=0, microsecond=0
        ) - datetime.timedelta(days=2)
        args = argparse.Namespace()
        log_type = "foo"
        backend = MockBackend()
        backend.get_metrics = mock.MagicMock(
            return_value=BackendResponse(
                data=MetricsResponse(
                    bytes_processed_per_source=[
                        SeriesWithBreakdown(
                            breakdown={
                                hour.isoformat(): 100,
                                (hour + datetime.timedelta(hours=1)).isoformat(): 50,
                            },
                            label=log_type,
                            value=150,
                        )
                    ]
                ),
                status_code=200,
            )
        )
        ret = validate_hour(args, log_type, backend)
        self.assertIsInstance(ret, datetime.datetime)
        self.assertEqual(hour, ret)

    def test_validate_hour_happy_path_provided_truncate(self) -> None:
        hour = datetime.datetime.now().astimezone() - datetime.timedelta(days=2)
        truncated_hour = hour.replace(minute=0, second=0, microsecond=0)
        args = argparse.Namespace(hour=hour)
        log_type = "foo"
        backend = MockBackend()
        backend.get_metrics = mock.MagicMock(
            return_value=BackendResponse(
                data=MetricsResponse(
                    bytes_processed_per_source=[
                        SeriesWithBreakdown(
                            breakdown={truncated_hour.isoformat(): 100}, label=log_type, value=150
                        )
                    ]
                ),
                status_code=200,
            )
        )
        ret = validate_hour(args, log_type, backend)
        self.assertIsInstance(ret, datetime.datetime)
        self.assertEqual(truncated_hour, ret)

    def test_validate_hour_provided_missing_log_type(self) -> None:
        hour = datetime.datetime.now().astimezone().replace(
            minute=0, second=0, microsecond=0
        ) - datetime.timedelta(days=2)
        args = argparse.Namespace(hour=hour)
        log_type = "foo"
        backend = MockBackend()
        backend.get_metrics = mock.MagicMock(
            return_value=BackendResponse(
                data=MetricsResponse(
                    bytes_processed_per_source=[
                        SeriesWithBreakdown(
                            breakdown={hour.isoformat(): 100}, label=log_type + "1", value=150
                        )
                    ]
                ),
                status_code=200,
            )
        )
        ret = validate_hour(args, log_type, backend)
        self.assertIsInstance(ret, str)
        self.assertIn(log_type, ret)

    def test_validate_hour_default_missing_log_type(self) -> None:
        hour = datetime.datetime.now().astimezone().replace(
            minute=0, second=0, microsecond=0
        ) - datetime.timedelta(days=2)
        args = argparse.Namespace()
        log_type = "foo"
        backend = MockBackend()
        backend.get_metrics = mock.MagicMock(
            return_value=BackendResponse(
                data=MetricsResponse(
                    bytes_processed_per_source=[
                        SeriesWithBreakdown(
                            breakdown={
                                hour.isoformat(): 100,
                                (hour + datetime.timedelta(hours=1)).isoformat(): 50,
                            },
                            label=log_type + "1",
                            value=150,
                        )
                    ]
                ),
                status_code=200,
            )
        )
        ret = validate_hour(args, log_type, backend)
        self.assertIsInstance(ret, str)
        self.assertIn(log_type, ret)

    def test_validate_hour_provided_too_old(self) -> None:
        hour = datetime.datetime.now().astimezone().replace(
            minute=0, second=0, microsecond=0
        ) - datetime.timedelta(weeks=3)
        args = argparse.Namespace(hour=hour)
        log_type = "foo"
        backend = MockBackend()
        backend.get_metrics = mock.MagicMock(
            return_value=BackendResponse(
                data=MetricsResponse(
                    bytes_processed_per_source=[
                        SeriesWithBreakdown(
                            breakdown={hour.isoformat(): 100}, label=log_type, value=150
                        )
                    ]
                ),
                status_code=200,
            )
        )
        ret = validate_hour(args, log_type, backend)
        self.assertIsInstance(ret, str)
        self.assertIn(hour.isoformat(), ret)

    def test_validate_hour_provided_empty_series(self) -> None:
        hour = datetime.datetime.now().astimezone().replace(
            minute=0, second=0, microsecond=0
        ) - datetime.timedelta(days=2)
        args = argparse.Namespace(hour=hour)
        log_type = "foo"
        backend = MockBackend()
        backend.get_metrics = mock.MagicMock(
            return_value=BackendResponse(
                data=MetricsResponse(
                    bytes_processed_per_source=[
                        SeriesWithBreakdown(breakdown=dict(), label=log_type, value=150)
                    ]
                ),
                status_code=200,
            )
        )
        ret = validate_hour(args, log_type, backend)
        self.assertIsInstance(ret, str)
        self.assertIn(log_type, ret)

    def test_validate_hour_default_empty_series(self) -> None:
        hour = datetime.datetime.now().astimezone().replace(
            minute=0, second=0, microsecond=0
        ) - datetime.timedelta(days=2)
        args = argparse.Namespace()
        log_type = "foo"
        backend = MockBackend()
        backend.get_metrics = mock.MagicMock(
            return_value=BackendResponse(
                data=MetricsResponse(
                    bytes_processed_per_source=[
                        SeriesWithBreakdown(breakdown=dict(), label=log_type, value=150)
                    ]
                ),
                status_code=200,
            )
        )
        ret = validate_hour(args, log_type, backend)
        self.assertIsInstance(ret, str)
        self.assertIn(log_type, ret)

    def test_validate_hour_provided_zeroed_series(self) -> None:
        hour = datetime.datetime.now().astimezone().replace(
            minute=0, second=0, microsecond=0
        ) - datetime.timedelta(days=2)
        args = argparse.Namespace(hour=hour)
        log_type = "foo"
        backend = MockBackend()
        backend.get_metrics = mock.MagicMock(
            return_value=BackendResponse(
                data=MetricsResponse(
                    bytes_processed_per_source=[
                        SeriesWithBreakdown(
                            breakdown={hour.isoformat(): 0}, label=log_type, value=150
                        )
                    ]
                ),
                status_code=200,
            )
        )
        ret = validate_hour(args, log_type, backend)
        self.assertIsInstance(ret, str)
        self.assertIn(log_type, ret)

    def test_validate_hour_default_zeroed_series(self) -> None:
        hour = datetime.datetime.now().astimezone().replace(
            minute=0, second=0, microsecond=0
        ) - datetime.timedelta(days=2)
        args = argparse.Namespace()
        log_type = "foo"
        backend = MockBackend()
        backend.get_metrics = mock.MagicMock(
            return_value=BackendResponse(
                data=MetricsResponse(
                    bytes_processed_per_source=[
                        SeriesWithBreakdown(
                            breakdown={
                                hour.isoformat(): 0,
                                (hour + datetime.timedelta(hours=1)).isoformat(): 0,
                            },
                            label=log_type,
                            value=150,
                        )
                    ]
                ),
                status_code=200,
            )
        )
        ret = validate_hour(args, log_type, backend)
        self.assertIsInstance(ret, str)
        self.assertIn(log_type, ret)

    def test_validate_hour_provided_too_many_stats(self) -> None:
        hour = datetime.datetime.now().astimezone().replace(
            minute=0, second=0, microsecond=0
        ) - datetime.timedelta(days=2)
        args = argparse.Namespace(hour=hour)
        log_type = "foo"
        backend = MockBackend()
        backend.get_metrics = mock.MagicMock(
            return_value=BackendResponse(
                data=MetricsResponse(
                    bytes_processed_per_source=[
                        SeriesWithBreakdown(
                            breakdown={
                                hour.isoformat(): 100,
                                (hour + datetime.timedelta(hours=1)).isoformat(): 50,
                            },
                            label=log_type,
                            value=150,
                        )
                    ]
                ),
                status_code=200,
            )
        )
        ret = validate_hour(args, log_type, backend)
        self.assertIsInstance(ret, str)
