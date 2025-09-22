from typing import Tuple

from panther_analysis_tool.analysis_utils import load_analysis_specs_ex
from panther_analysis_tool.core import format


def run() -> Tuple[int, str]:
    return format_specs()


def format_specs() -> Tuple[int, str]:
    specs = load_analysis_specs_ex(["."], [], False)

    for spec in specs:
        spec.analysis_spec = format.analysis_spec_dump(spec.analysis_spec, sort=True)
        with open(spec.spec_filename, "w") as f:
            f.write(spec.analysis_spec)

    return 0, ""
