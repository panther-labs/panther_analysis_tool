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
import re
import traceback
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import List, Optional, Type

from panther_analysis_tool.util import id_to_path, import_file_as_module, store_modules

# Temporary alias for compatibility
get_logger = logging.getLogger

# pylint: disable=too-many-instance-attributes,unsubscriptable-object
@dataclass
class DetectionResult:
    """Class containing the result of running a detection"""

    detection_id: str
    detection_severity: str
    detection_type: str
    trigger_alert: bool  # detection output, default to non-alerting value

    setup_exception: Optional[Exception] = None

    detection_output: Optional[bool] = None
    detection_exception: Optional[Exception] = None

    dedup_output: Optional[str] = None
    dedup_exception: Optional[Exception] = None
    dedup_defined: bool = False

    title_output: Optional[str] = None
    title_exception: Optional[Exception] = None
    title_defined: bool = False

    description_output: Optional[str] = None
    description_exception: Optional[Exception] = None
    description_defined: bool = False

    reference_output: Optional[str] = None
    reference_exception: Optional[Exception] = None
    reference_defined: bool = False

    severity_output: Optional[str] = None
    severity_exception: Optional[Exception] = None
    severity_defined: bool = False

    runbook_output: Optional[str] = None
    runbook_exception: Optional[Exception] = None
    runbook_defined: bool = False

    destinations_output: Optional[List[str]] = None
    destinations_exception: Optional[Exception] = None
    destinations_defined: bool = False

    alert_context_output: Optional[str] = None
    alert_context_exception: Optional[Exception] = None
    alert_context_defined: bool = False

    input_exception: Optional[Exception] = None

    @property
    def fatal_error(self) -> Optional[Exception]:
        """Provide any error that would stop evaluation
        or None, if no blocking error is found"""
        exception = None
        if self.setup_exception:
            exception = self.setup_exception
        elif self.detection_exception:
            exception = self.detection_exception
        elif self.input_exception:
            exception = self.input_exception
        return exception

    @property
    def error_type(self) -> Optional[str]:
        """Returns the type of the exception, None if there was no error"""
        fatal_error = self.fatal_error
        if fatal_error is None:
            return None
        return type(fatal_error).__name__

    @property
    def short_error_message(self) -> Optional[str]:
        """Returns short error message, None if there was no error"""
        fatal_error = self.fatal_error
        if fatal_error is None:
            return None
        return repr(fatal_error)

    @property
    def error_message(self) -> Optional[str]:
        """Returns formatted error message with traceback"""
        exception = self.fatal_error
        if exception is None:
            return None

        trace = traceback.format_tb(exception.__traceback__)
        # we only take last element of trace which will show the
        # detection file name and line of the error, for example:
        #    division by zero: AlwaysFail.py, line 4, in detection 1/0
        file_trace = trace[len(trace) - 1].strip().replace("\n", "")
        # this looks like: File "/tmp/rules/AlwaysFail.py", line 4, in detection 1/0 BUT
        # we want just the file name
        return str(exception) + ": " + re.sub(r'File.*/(.*[.]py)"', r"\1", file_trace)

    @property
    def errored(self) -> bool:
        """Returns whether any of the detection functions raised an error"""
        return bool(
            self.detection_exception
            or self.title_exception
            or self.dedup_exception
            or self.alert_context_exception
            or self.description_exception
            or self.reference_exception
            or self.severity_exception
            or self.runbook_exception
            or self.destinations_exception
            or self.setup_exception
            or self.input_exception
        )

    @property
    def detection_evaluation_failed(self) -> bool:
        """Returns whether the detection function raises an error or an import error occurred"""
        return bool(self.detection_exception or self.setup_exception)

    def ignore_errors(self, ignore_exception_types: List[Type[Exception]]) -> None:
        """Used to ignore exceptions of particular types, used primarily in testing"""
        for exception_type in ignore_exception_types:
            if isinstance(self.detection_exception, exception_type):
                self.detection_exception = None
            if isinstance(self.title_exception, exception_type):
                self.title_exception = None
            if isinstance(self.description_exception, exception_type):
                self.description_exception = None
            if isinstance(self.reference_exception, exception_type):
                self.reference_exception = None
            if isinstance(self.severity_exception, exception_type):
                self.severity_exception = None
            if isinstance(self.runbook_exception, exception_type):
                self.runbook_exception = None
            if isinstance(self.destinations_exception, exception_type):
                self.destinations_exception = None
            if isinstance(self.dedup_exception, exception_type):
                self.dedup_exception = None
            if isinstance(self.alert_context_exception, exception_type):
                self.alert_context_exception = None


class BaseImporter:
    """Base class for Python module importers"""

    @staticmethod
    def from_file(identifier: str, path: str) -> ModuleType:
        """Import a file as a Python module"""
        return import_file_as_module(path, identifier)

    def from_string(self, identifier: str, body: str, tmp_dir: str) -> ModuleType:
        """Write source code to a temporary file and import as Python module"""
        path = id_to_path(tmp_dir, identifier)
        store_modules(path, body)
        return self.from_file(identifier, path)

    @abstractmethod
    def get_module(self, identifier: str, resource: str) -> ModuleType:
        pass


class FilesystemImporter(BaseImporter):
    """Import a Python module from the filesystem"""

    def get_module(  # pylint: disable=arguments-differ
        self, identifier: str, path: str
    ) -> ModuleType:
        module_path = Path(path)
        if not module_path.exists():
            raise FileNotFoundError(path)
        return super().from_file(identifier, module_path.absolute().as_posix())


class RawStringImporter(BaseImporter):
    """Import a Python module from raw source code"""

    def __init__(self, tmp_dir: str):
        super().__init__()
        self._tmp_dir = tmp_dir

    def get_module(  # pylint: disable=arguments-differ
        self, identifier: str, body: str
    ) -> ModuleType:
        return super().from_string(identifier, body, self._tmp_dir)
