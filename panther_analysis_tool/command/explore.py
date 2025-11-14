from panther_analysis_tool import analysis_utils
from panther_analysis_tool.core import analysis_cache, versions_file, yaml
from panther_analysis_tool.gui.explore_gui import ExploreApp


def run() -> tuple[int, str]:
    all_specs = load_all_specs()
    app = ExploreApp(all_specs)
    app.run()
    return 0, ""


def load_all_specs() -> list[analysis_utils.AnalysisItem]:
    yaml_loader = yaml.BlockStyleYAML()
    cache = analysis_cache.AnalysisCache()
    versions = versions_file.get_versions().versions

    specs: list[analysis_utils.AnalysisItem] = []
    for _id in cache.list_spec_ids():
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
