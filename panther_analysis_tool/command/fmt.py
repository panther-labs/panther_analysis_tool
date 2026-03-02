import pathlib

from panther_analysis_tool import analysis_utils


def run() -> tuple[int, str]:
    fmt()
    return 0, ""


def fmt() -> None:
    for item in analysis_utils.load_analysis_specs_ex(["."], [], True):
        item.yaml_ctx.dump(item.analysis_spec, pathlib.Path(item.spec_filename))
