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
import json
import logging
import os
from fnmatch import fnmatch
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ruamel.yaml import YAML
from ruamel.yaml import parser as YAMLParser
from ruamel.yaml import scanner as YAMLScanner

from panther_analysis_tool.backend.client import BackendError
from panther_analysis_tool.backend.client import Client as BackendClient
from panther_analysis_tool.backend.client import TranspileToPythonParams
from panther_analysis_tool.constants import (
    DATA_MODEL_PATH_PATTERN,
    HELPERS_PATH_PATTERN,
    LUTS_PATH_PATTERN,
    PACKS_PATH_PATTERN,
    POLICIES_PATH_PATTERN,
    QUERIES_PATH_PATTERN,
    RULES_PATH_PATTERN,
)


class ClassifiedAnalysis:
    def __init__(self, file_name: str, dir_name: str, analysis_spec: Dict[str, Any]):
        self.file_name = file_name
        self.dir_name = dir_name
        self.analysis_spec = analysis_spec


def filter_analysis(
    analysis: List[ClassifiedAnalysis], filters: Dict[str, List], filters_inverted: Dict[str, List]
) -> List[ClassifiedAnalysis]:
    if filters is None:
        return analysis

    filtered_analysis = []
    for item in analysis:
        dir_name = item.dir_name
        file_name = item.file_name
        analysis_spec = item.analysis_spec
        if fnmatch(dir_name, HELPERS_PATH_PATTERN):
            logging.debug("auto-adding helpers file %s", os.path.join(file_name))
            filtered_analysis.append(ClassifiedAnalysis(file_name, dir_name, analysis_spec))
            continue
        if fnmatch(dir_name, DATA_MODEL_PATH_PATTERN):
            logging.debug("auto-adding data model file %s", os.path.join(file_name))
            filtered_analysis.append(ClassifiedAnalysis(file_name, dir_name, analysis_spec))
            continue
        match = True
        for key, values in filters.items():
            spec_value = analysis_spec.get(key, "")
            spec_value = spec_value if isinstance(spec_value, list) else [spec_value]
            if not set(spec_value).intersection(values):
                match = False
                break
        for key, values in filters_inverted.items():
            spec_value = analysis_spec.get(key, "")
            spec_value = spec_value if isinstance(spec_value, list) else [spec_value]
            if set(spec_value).intersection(values):
                match = False
                break

        if match:
            filtered_analysis.append(ClassifiedAnalysis(file_name, dir_name, analysis_spec))

    return filtered_analysis


def load_analysis_specs(
    directories: List[str], ignore_files: List[str]
) -> Iterator[Tuple[str, str, Any, Any]]:
    """Loads the analysis specifications from a file.

    Args:
        directories: The relative path to Panther policies or rules.
        ignore_files: Files that Panther Analysis Tool should not process

    Yields:
        A tuple of the relative filepath, directory name, and loaded analysis specification dict.
    """
    # setup a list of paths to ensure we do not import the same files
    # multiple times, which can happen when testing from root directory without filters
    ignored_normalized = []
    for file in ignore_files:
        ignored_normalized.append(os.path.normpath(file))

    loaded_specs: List[Any] = []
    for directory in directories:
        for relative_path, _, file_list in os.walk(directory):
            # Skip hidden folders
            if (
                relative_path.split("/")[-1].startswith(".")
                and relative_path != "./"
                and relative_path != "."
            ):
                continue
            # setup yaml object
            yaml = YAML(typ="safe")
            # If the user runs with no path args, filter to make sure
            # we only run folders with valid analysis files. Ensure we test
            # files in the current directory by not skipping this iteration
            # when relative_path is the current dir
            if directory in [".", "./"] and relative_path not in [".", "./"]:
                if not any(
                    (
                        fnmatch(relative_path, path_pattern)
                        for path_pattern in (
                            DATA_MODEL_PATH_PATTERN,
                            HELPERS_PATH_PATTERN,
                            LUTS_PATH_PATTERN,
                            RULES_PATH_PATTERN,
                            PACKS_PATH_PATTERN,
                            POLICIES_PATH_PATTERN,
                            QUERIES_PATH_PATTERN,
                        )
                    )
                ):
                    logging.debug("Skipping path %s", relative_path)
                    continue
            for filename in sorted(file_list):
                # Skip hidden files
                if filename.startswith("."):
                    continue
                spec_filename = os.path.abspath(os.path.join(relative_path, filename))
                # skip loading files that have already been imported
                if spec_filename in loaded_specs:
                    continue
                # Dont load files that are explictly ignored
                relative_name = os.path.normpath(os.path.join(relative_path, filename))
                if relative_name in ignored_normalized:
                    logging.info("ignoring file %s", relative_name)
                    continue
                loaded_specs.append(spec_filename)
                if fnmatch(filename, "*.y*ml"):
                    with open(spec_filename, "r") as spec_file_obj:
                        try:
                            yield spec_filename, relative_path, yaml.load(spec_file_obj), None
                        except (YAMLParser.ParserError, YAMLScanner.ScannerError) as err:
                            # recreate the yaml object and yield the error
                            yaml = YAML(typ="safe")
                            yield spec_filename, relative_path, None, err
                if fnmatch(filename, "*.json"):
                    with open(spec_filename, "r") as spec_file_obj:
                        try:
                            yield spec_filename, relative_path, json.load(spec_file_obj), None
                        except ValueError as err:
                            yield spec_filename, relative_path, None, err


def to_relative_path(filename: str) -> str:
    cwd = os.getcwd()
    return os.path.relpath(filename, cwd)


# This function was generated in whole or in part by GitHub Copilot.
def get_simple_detections_as_python(
    specs: List[ClassifiedAnalysis], backend: Optional[BackendClient] = None
) -> List[ClassifiedAnalysis]:
    """Returns simple detections with transpiled Python."""
    enriched_specs = []
    if backend is not None:
        batch = [json.dumps(spec.analysis_spec) for spec in specs]
        try:
            params = TranspileToPythonParams(data=batch)
            response = backend.transpile_simple_detection_to_python(params)
            if response.status_code == 200:
                for i, result in enumerate(response.data.transpiled_python):
                    item = specs[i]
                    spec = item.analysis_spec
                    spec["body"] = result
                    enriched_specs.append(ClassifiedAnalysis(item.file_name, item.dir_name, spec))
            else:
                logging.warning(
                    "Error transpiling simple detection(s) to Python, skipping tests for simple detections."
                )
        except (BackendError, BaseException) as be_err:  # pylint: disable=broad-except
            logging.warning(
                "Error transpiling simple detection(s) to Python, skipping tests for simple detections:  %s",
                be_err,
            )
    else:
        logging.info("No backend client provided, skipping tests for simple detections.")
    return enriched_specs if enriched_specs else specs
