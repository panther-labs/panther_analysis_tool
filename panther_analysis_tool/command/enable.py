import logging
from typing import Any, Optional, Tuple

from panther_analysis_tool.command.clone import clone_analysis
from panther_analysis_tool.constants import AnalysisTypes


def run(analysis_id: Optional[str], **kwargs) -> Tuple[int, str]:
    def mutator(spec: Any) -> Any:
        if spec["AnalysisType"] in [AnalysisTypes.RULE, AnalysisTypes.SCHEDULED_RULE]:
            spec["Enabled"] = True
        return spec

    clone_analysis(analysis_id, filter=kwargs["filter"], mutator=mutator)
    return 0, ""
