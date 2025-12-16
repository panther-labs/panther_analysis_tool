from rich.progress import track

from panther_analysis_tool import analysis_utils
from panther_analysis_tool.core import analysis_cache, git_helpers, versions_file, yaml
from panther_analysis_tool.gui.explore_gui import ExploreApp


def run() -> tuple[int, str]:
    git_helpers.chdir_to_git_root()
    analysis_cache.update_with_latest_panther_analysis(show_progress_bar=True)
    all_specs = load_panther_analysis_specs(show_progress_bar=True)
    user_spec_ids = load_user_specs(show_progress_bar=True)
    app = ExploreApp(
        all_specs=all_specs,
        user_spec_ids=user_spec_ids,
    )
    app.run()
    return 0, ""


def load_panther_analysis_specs(
    show_progress_bar: bool = False,
) -> list[analysis_utils.AnalysisItem]:
    yaml_loader = yaml.BlockStyleYAML()
    cache = analysis_cache.AnalysisCache()
    versions = versions_file.get_versions().versions

    specs: list[analysis_utils.AnalysisItem] = []
    for _id in track(
        cache.list_spec_ids(),
        description="Loading all specs:",
        disable=not show_progress_bar,
        transient=True,
    ):
        spec = cache.get_latest_spec(_id)
        if spec is None:
            continue

        yaml_content = yaml_loader.load(spec.spec)
        ver = versions[_id]

        item = analysis_utils.AnalysisItem(
            yaml_file_contents=yaml_content,
            raw_yaml_file_contents=spec.spec,
            yaml_file_path=ver.history[ver.version].yaml_file_path,
        )

        if "Filename" in yaml_content:
            python_file_contents = cache.get_file_for_spec(spec.id or -1, spec.version)
            item.python_file_contents = python_file_contents
            item.python_file_path = ver.history[ver.version].py_file_path

        specs.append(item)

    return specs


def load_user_specs(show_progress_bar: bool = False) -> set[str]:
    spec_ids: set[str] = set()
    for spec in track(
        analysis_utils.load_analysis_specs_ex(["."], [], True),
        description="Loading user analysis items:",
        disable=not show_progress_bar,
        transient=True,
    ):
        spec_ids.add(spec.analysis_id())
    return spec_ids
