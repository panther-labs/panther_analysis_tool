from typing import Tuple
import os

def run() -> Tuple[int, str]:
    setup_folder_structure()
    return 0, "Project initialized"

def setup_folder_structure() -> None:
    # os.makedirs("correlation_rules", exist_ok=True)
    # os.makedirs("data_models", exist_ok=True)
    # os.makedirs("global_helpers", exist_ok=True)
    # os.makedirs("lookup_tables", exist_ok=True)
    # os.makedirs("policies", exist_ok=True)
    # os.makedirs("queries", exist_ok=True)
    # os.makedirs("rules", exist_ok=True)
    
    if not os.path.exists(".gitignore"):
        with open(".gitignore", "w") as f:
            f.write("*.cache/\n")
