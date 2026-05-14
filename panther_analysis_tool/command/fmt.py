import pathlib

from panther_analysis_tool import analysis_utils


def run() -> tuple[int, str]:
    errors = fmt()
    if errors:
        msg = "fmt failed to parse the following files; they were left unchanged:\n" + "\n".join(
            f"  {filename}: {err}" for filename, err in errors
        )
        return 1, msg
    return 0, ""


def fmt() -> list[tuple[str, Exception]]:
    errors: list[tuple[str, Exception]] = []
    for item in analysis_utils.load_analysis_specs_ex(["."], [], True):
        if item.error is not None or item.analysis_spec is None:
            errors.append((item.spec_filename, item.error or ValueError("empty spec")))
            continue
        item.yaml_ctx.dump(item.analysis_spec, pathlib.Path(item.spec_filename))
    return errors
