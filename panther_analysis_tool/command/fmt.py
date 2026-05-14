import dataclasses
import pathlib

from panther_analysis_tool import analysis_utils


@dataclasses.dataclass(frozen=True)
class FmtError:
    spec_filename: str
    error: Exception


def run() -> tuple[int, str]:
    errors = fmt()
    if errors:
        msg = "fmt failed to parse the following files; they were left unchanged:\n" + "\n".join(
            f"  {e.spec_filename}: {e.error}" for e in errors
        )
        return 1, msg
    return 0, ""


def fmt() -> list[FmtError]:
    errors: list[FmtError] = []
    for item in analysis_utils.load_analysis_specs_ex(["."], [], True):
        if item.error is not None or item.analysis_spec is None:
            errors.append(
                FmtError(item.spec_filename, item.error or ValueError("empty spec"))
            )
            continue
        item.yaml_ctx.dump(item.analysis_spec, pathlib.Path(item.spec_filename))
    return errors
