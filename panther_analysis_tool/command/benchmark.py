import argparse
import datetime
import io
import sys
import zipfile
from statistics import mean, median
from typing import List, Optional, Tuple, Union

import dateutil.parser

from panther_analysis_tool.analysis_utils import ClassifiedAnalysis
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import MetricsParams, PerfTestParams
from panther_analysis_tool.constants import AnalysisTypes, ReplayStatus
from panther_analysis_tool.util import log_and_write_to_file
from panther_analysis_tool.zip_chunker import (
    ZipArgs,
    analysis_for_chunks,
    chunk_analysis,
)


class PerformanceTestIteration:
    def __init__(self, read_time_nanos: int, processing_time_nanos: int) -> None:
        self.read_time_nanos = read_time_nanos
        self.processing_time_nanos = processing_time_nanos

    def __str__(self) -> str:
        return (
            f"Read time (nanoseconds): {self.read_time_nanos}\n"
            f"Processing time (nanoseconds): {self.processing_time_nanos}"
        )


def run(  # pylint: disable=too-many-locals
    backend: BackendClient, args: argparse.Namespace
) -> Tuple[int, str]:
    if backend is None or not backend.supports_perf_test():
        return 1, "Invalid backend. `benchmark` is only supported via API token"

    if args.iterations <= 0:
        return 1, f"benchmark must perform at least 1 iteration, {args.iterations} requested"

    analyses = analysis_for_chunks(ZipArgs.from_args(args), no_helpers=True)

    rule_or_err = validate_rule_count(analyses)
    if isinstance(rule_or_err, str):
        return 1, rule_or_err

    log_type, err_msg = validate_log_type(args, rule_or_err)
    if err_msg is not None or not isinstance(log_type, str):
        return 1, err_msg or "No log_type found"

    hour_or_err = validate_hour(args, log_type, backend)
    if isinstance(hour_or_err, str):
        return 1, hour_or_err

    chunks = chunk_analysis(analyses)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zip_out:
        for name in chunks[0].files:
            zip_out.write(name)
    buffer.seek(0, 0)

    now = datetime.datetime.now()
    timeout = now + datetime.timedelta(minutes=13)

    params = PerfTestParams(
        zip_bytes=buffer.read(),
        log_type=log_type,
        hour=hour_or_err,
        timeout=timeout.astimezone(),
    )
    iterations: List[PerformanceTestIteration] = []
    logged = False
    for _ in range(0, args.iterations):
        replay_response = backend.run_perf_test(params)
        if replay_response.data.state == ReplayStatus.CANCELED:
            if len(iterations) == 0:
                log_extreme_timeout(args, hour_or_err, now)
                logged = True
            break
        if replay_response.data.state in [
            ReplayStatus.ERROR_EVALUATION,
            ReplayStatus.ERROR_COMPUTATION,
        ]:
            log_error(args, hour_or_err, now)
            if len(iterations) == 0:
                logged = True
            break
        iterations.append(
            PerformanceTestIteration(
                read_time_nanos=replay_response.data.replay_summary.read_time_nanos,
                processing_time_nanos=replay_response.data.replay_summary.processing_time_nanos,
            )
        )

    if not logged:
        log_output(args, hour_or_err, iterations, rule_or_err, now)

    return 0, ""


def validate_rule_count(analyses: List[ClassifiedAnalysis]) -> Union[ClassifiedAnalysis, str]:
    if len(analyses) != 1:
        return (
            f"Only 1 detection must be specified for benchmarking, but {len(analyses)} were specified. The rule must"
            f" be the only item in the working directory or specified by --path, --ignore-files, and/or --filter. The"
            f" following files were provided (up to 10 shown):"
            f" {[a.file_name for a in analyses[:10]]}"
        )
    analysis = analyses[0]
    if analysis.analysis_spec["AnalysisType"] != AnalysisTypes.RULE:
        return (
            f"Only rules are supported for performance testing, but {analysis.analysis_spec['AnalysisType']}"
            f" was provided in {analysis.file_name}"
        )
    return analysis


def validate_log_type(
    args: argparse.Namespace, rule: ClassifiedAnalysis
) -> Tuple[Optional[str], Optional[str]]:
    log_type = getattr(args, "log_type", None)
    rule_log_types = rule.analysis_spec.get("LogTypes", [])
    if log_type is None:
        if len(rule_log_types) > 1:
            return (
                log_type,
                f"Multiple log types specified for {rule.file_name}: {rule_log_types}, please use the"
                f" --log-type arg to specify one.",
            )
        log_type = rule_log_types[0]
    else:
        if not str(log_type).casefold() in map(str.casefold, rule_log_types):
            return (
                log_type,
                f"Provided log type {log_type} was not found in log types for {rule.file_name}:"
                f" {rule_log_types}",
            )
    return log_type, None


def validate_hour(
    args: argparse.Namespace, log_type: str, backend: BackendClient
) -> Union[datetime.datetime, str]:
    hour = getattr(args, "hour", None)
    now_truncated = datetime.datetime.now().replace(
        minute=0, second=0, microsecond=0
    ).astimezone() + datetime.timedelta(microseconds=-1)
    window_begin = now_truncated + datetime.timedelta(weeks=-2, microseconds=1)
    if hour is None:
        end_time = now_truncated
        start_time = window_begin
        err_msg = (
            f"No data found on Panther for log_type {log_type} in past two weeks. This can occur if"
            f" ingestion began within the last 24 hours."
        )
    else:
        if hour < window_begin:
            return f"Provided hour {hour.isoformat()} is too old. Please provide a time no older than {window_begin}"
        start_time = hour.replace(minute=0, second=0, microsecond=0)
        end_time = start_time + datetime.timedelta(hours=1, microseconds=-1)
        hour = start_time
        err_msg = (
            f"No data found on Panther for log_type {log_type} at specified hour: {hour.isoformat()}. Please"
            f" try another hour or leave the argument blank and one will be selected for you."
        )
    metrics_response = backend.get_metrics(
        MetricsParams(
            from_date=start_time,
            to_date=end_time,
            interval_in_minutes=60,
        )
    )
    data_for_log_type = next(
        (
            x
            for x in metrics_response.data.bytes_processed_per_source
            if x.label.casefold() == log_type.casefold()
        ),
        None,
    )
    if data_for_log_type is None:
        return err_msg

    if hour is not None and len(data_for_log_type.breakdown) > 1:
        return (
            "Internal error: time window too large. Please report this error to someone at Panther."
        )

    max_data_hour = max(  # type: ignore
        data_for_log_type.breakdown, key=data_for_log_type.breakdown.get, default=None
    )
    if max_data_hour is None or data_for_log_type.breakdown[max_data_hour] == 0:
        return err_msg
    hour = dateutil.parser.parse(max_data_hour)

    return hour


def generate_command_log_text(hour: datetime.datetime) -> List[str]:
    command = sys.argv[1:].copy()
    if "--hour" not in command:
        command.append("--hour")
        command.append(hour.isoformat())

    return [
        "To reproduce this benchmark on the same environment, please run:",
        "panther_analysis_tool " + " ".join(command),
    ]


def write_output(args: argparse.Namespace, to_write: List[str], now: datetime.datetime) -> None:
    with open(args.out + f"/benchmark-{int(now.timestamp())}", "a") as filename:
        to_write.insert(0, f"Writing to file: {filename.name}")
        log_and_write_to_file(to_write, filename)


def nanos_to_seconds(nanos: float) -> float:
    return datetime.timedelta(microseconds=nanos / 1000).total_seconds()


def log_output(
    args: argparse.Namespace,
    hour: datetime.datetime,
    iterations: List[PerformanceTestIteration],
    rule: ClassifiedAnalysis,
    now: datetime.datetime,
) -> None:
    to_write = generate_command_log_text(hour)

    median_read_time_nanos = median([i.read_time_nanos for i in iterations])
    median_processing_time_nanos = median([i.processing_time_nanos for i in iterations])

    median_in_minutes = nanos_to_seconds(median_read_time_nanos + median_processing_time_nanos) / 60
    descriptor_string = "Less performant"
    if median_in_minutes < 1:
        descriptor_string = "Highly performant"
    elif median_in_minutes >= 10:
        descriptor_string = "At risk of timing out"

    to_write.extend(
        [
            "",
            f"Performance tested over {len(iterations)} iterations",
            f"Mean read time (seconds): {nanos_to_seconds(mean([i.read_time_nanos for i in iterations]))}",
            f"Median read time (seconds): {nanos_to_seconds(median_read_time_nanos)}",
            f"Max read time (seconds): {nanos_to_seconds(max([i.read_time_nanos for i in iterations]))}",
            f"Min read time (seconds): {nanos_to_seconds(min([i.read_time_nanos for i in iterations]))}",
            f"Mean processing time (seconds): {nanos_to_seconds(mean([i.processing_time_nanos for i in iterations]))}",
            f"Median processing time (seconds): {nanos_to_seconds(median_processing_time_nanos)}",
            f"Max processing time (seconds): {nanos_to_seconds(max([i.processing_time_nanos for i in iterations]))}",
            f"Min processing time (seconds): {nanos_to_seconds(min([i.processing_time_nanos for i in iterations]))}",
            "",
            "Detection performance ranges:",
            "< 1 minute: Highly performant",
            "1 minute to 10 minutes: Less performant, but unlikely to cause issues unless running alongside other less"
            " performant rules",
            "10+ minutes: At risk of timing out. Please improve performance",
            "",
            f"*** Rule {rule.file_name} is: {descriptor_string} ***",
            "",
            "Full record:",
        ]
    )
    to_write.extend([str(iteration) + "\n-----" for iteration in iterations])

    write_output(args, to_write, now)


def log_extreme_timeout(
    args: argparse.Namespace,
    hour: datetime.datetime,
    now: datetime.datetime,
) -> None:
    to_write = generate_command_log_text(hour)
    to_write.append(
        "Your detection has timed out before completing the benchmark one hour of data! Please improve performance."
    )
    write_output(args, to_write, now)


def log_error(args: argparse.Namespace, hour: datetime.datetime, now: datetime.datetime) -> None:
    to_write = generate_command_log_text(hour)
    to_write.append("benchmark failed with an error. Please ensure the correctness of your rule.")
    write_output(args, to_write, now)
