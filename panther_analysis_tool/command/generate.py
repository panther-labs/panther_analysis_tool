import importlib.util
import logging
import os

from panther_analysis_tool.core import root


def run() -> tuple[int, str]:
    root.chdir_to_project_root()
    generate()
    return 0, "Success"


def generate() -> None:
    """Load and execute the main.py file from the project root.

    The main.py file will have access to the analysis items API:
    - load_analysis_items() - Load and filter analysis items
    - write_analysis_items() - Write modified items back to disk
    - All type-specific wrapper classes (RuleItem, PolicyItem, etc.)
    """
    main_py_path = os.path.join(os.getcwd(), "main.py")

    if not os.path.exists(main_py_path):
        raise FileNotFoundError(f"main.py not found in project root: {os.getcwd()}")

    logging.debug("Loading and executing main.py from %s", main_py_path)

    # Load and execute the main.py module with API in namespace
    spec = importlib.util.spec_from_file_location("main", main_py_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Could not create module spec for {main_py_path}")

    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore
    except Exception as err:  # pylint: disable=broad-except
        raise Exception(f"Error executing main.py: {str(err)}") from err
