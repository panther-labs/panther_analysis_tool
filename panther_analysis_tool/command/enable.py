from typing import Any, List, Optional, Tuple

from panther_analysis_tool.command.clone import clone_analysis
from panther_analysis_tool.constants import AnalysisTypes


def run(analysis_id: Optional[str], filters: List[str]) -> Tuple[int, str]:
    def mutator(spec: Any) -> Any:
        if spec["AnalysisType"] in [AnalysisTypes.RULE, AnalysisTypes.SCHEDULED_RULE, AnalysisTypes.SAVED_QUERY, AnalysisTypes.SCHEDULED_QUERY]:
            spec["Enabled"] = True
        return spec

    clone_analysis(analysis_id, filters=filters, mutator=mutator)
    return 0, ""
