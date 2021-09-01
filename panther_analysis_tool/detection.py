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
from dataclasses import dataclass
from typing import List, Optional

# Temporary alias for compatibility
get_logger = logging.getLogger

# pylint: disable=too-many-instance-attributes,unsubscriptable-object
@dataclass
class DetectionResult:
    """Class containing the result of running a detection"""

    detection_id: str
    detection_severity: str
    detection_type: Optional[str] = None
    setup_exception: Optional[Exception] = None

    matched: Optional[bool] = None  # detection output
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
