import dataclasses
from typing import Any, Callable, DefaultDict, Dict, Generator, List, Optional

from panther_core.rule import Detection
from panther_core.testing import TestResult

from panther_analysis_tool.constants import AnalysisTypes
from panther_analysis_tool.util import is_simple_detection


class ClassifiedAnalysis:
    def __init__(self, file_name: str, dir_name: str, analysis_spec: Dict[str, Any]):
        self.file_name = file_name
        self.dir_name = dir_name
        self.analysis_spec = analysis_spec

    def is_deprecated(self) -> bool:
        display_name = self.analysis_spec["DisplayName"]
        description = self.analysis_spec.get("Description", "")
        if "deprecated" in display_name.lower() or "deprecated" in description.lower():
            return True

        tags = {tag.lower() for tag in self.analysis_spec.get("Tags", [])}
        if "deprecated" in tags:
            return True
        return False


@dataclasses.dataclass
class ClassifiedAnalysisContainer:
    """Contains all classified analysis specs"""

    data_models: List[ClassifiedAnalysis] = dataclasses.field(init=False, default_factory=list)
    globals: List[ClassifiedAnalysis] = dataclasses.field(init=False, default_factory=list)
    detections: List[ClassifiedAnalysis] = dataclasses.field(init=False, default_factory=list)
    simple_detections: List[ClassifiedAnalysis] = dataclasses.field(
        init=False, default_factory=list
    )
    queries: List[ClassifiedAnalysis] = dataclasses.field(init=False, default_factory=list)
    lookup_tables: List[ClassifiedAnalysis] = dataclasses.field(init=False, default_factory=list)
    packs: List[ClassifiedAnalysis] = dataclasses.field(init=False, default_factory=list)

    def _self_as_list(self) -> List[List[ClassifiedAnalysis]]:
        return [
            self.data_models,
            self.globals,
            self.detections,
            self.simple_detections,
            self.queries,
            self.lookup_tables,
            self.packs,
        ]

    def empty(self) -> bool:
        return all(len(l) == 0 for l in self._self_as_list())

    def apply(
        self,
        func: Callable[[List[ClassifiedAnalysis]], List[ClassifiedAnalysis]],
    ) -> "ClassifiedAnalysisContainer":
        container = ClassifiedAnalysisContainer()
        container.data_models = func(self.data_models)
        container.globals = func(self.globals)
        container.detections = func(self.detections)
        container.simple_detections = func(self.simple_detections)
        container.queries = func(self.queries)
        container.lookup_tables = func(self.lookup_tables)
        container.packs = func(self.packs)
        return container

    def items(self) -> Generator[ClassifiedAnalysis, None, None]:
        for analysis_list in self._self_as_list():
            for classified in analysis_list:
                yield classified

    def add_classified_analysis(
        self, analysis_type: str, classified_analysis: ClassifiedAnalysis
    ) -> None:
        if is_simple_detection(classified_analysis.analysis_spec):
            self.simple_detections.append(classified_analysis)
        elif analysis_type in [
            AnalysisTypes.POLICY,
            AnalysisTypes.RULE,
            AnalysisTypes.SCHEDULED_RULE,
            AnalysisTypes.CORRELATION_RULE,
        ]:
            self.detections.append(classified_analysis)
        elif analysis_type == AnalysisTypes.DATA_MODEL:
            self.data_models.append(classified_analysis)
        elif analysis_type == AnalysisTypes.GLOBAL:
            self.globals.append(classified_analysis)
        elif analysis_type == AnalysisTypes.LOOKUP_TABLE:
            self.lookup_tables.append(classified_analysis)
        elif analysis_type == AnalysisTypes.PACK:
            self.packs.append(classified_analysis)
        elif analysis_type == AnalysisTypes.SAVED_QUERY:
            self.queries.append(classified_analysis)
        elif analysis_type == AnalysisTypes.SCHEDULED_QUERY:
            self.queries.append(classified_analysis)


@dataclasses.dataclass
class TestResultContainer:
    detection: Optional[Detection]
    result: TestResult
    failed_tests: DefaultDict[str, list]
    output: str


@dataclasses.dataclass
class TestResultsContainer:
    """A container for all test results"""

    passed: Dict[str, List[TestResultContainer]]
    errored: Dict[str, List[TestResultContainer]]
