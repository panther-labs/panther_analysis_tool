import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from panther_analysis_tool.schemas import (
    GLOBAL_SCHEMA,
    POLICY_SCHEMA,
    RULE_SCHEMA,
    extract_keys_schema,
)


@dataclass
class Filter:
    key: str
    values: List[Any] | Any


# Parses the filters, expects a list of strings
def parse_filter(str_filters: Optional[List[str]]) -> Tuple[List[Filter], List[Filter]]:
    parsed_filters: Dict[str, Any] = {}
    parsed_filters_inverted: Dict[str, Any] = {}
    if str_filters is None:
        return [], []
    for filt in str_filters:
        split = filt.split("=")
        if len(split) != 2 or split[0] == "" or split[1] == "":
            logging.error("Filter %s is not in format KEY=VALUE", filt)
            exit(1)
        # Check for "!="
        invert_filter = split[0].endswith("!")
        if invert_filter:
            split[0] = split[0][:-1]  # Remove the trailing "!"
        key = split[0]
        valid_keys = (
            extract_keys_schema(GLOBAL_SCHEMA)
            | extract_keys_schema(POLICY_SCHEMA)
            | extract_keys_schema(RULE_SCHEMA)
        )
        if key not in valid_keys:
            logging.error("Filter key %s is not a valid filter field", key)
            exit(1)
        if invert_filter:
            parsed_filters_inverted[key] = split[1].split(",")
        else:
            parsed_filters[key] = split[1].split(",")
        # Handle boolean fields
        if key == "Enabled":
            try:
                bool_value = bool(strtobool(split[1]))
            except ValueError:
                logging.error("Filter key %s should have either true or false", key)
                exit(1)
            if invert_filter:
                parsed_filters_inverted[key] = [bool_value]
            else:
                parsed_filters[key] = [bool_value]

    filters = [Filter(key=key, values=values) for key, values in parsed_filters.items()]
    filters_inverted = [
        Filter(key=key, values=values) for key, values in parsed_filters_inverted.items()
    ]
    return filters, filters_inverted


def strtobool(val: str) -> int:
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return 1
    elif val in ("n", "no", "f", "false", "off", "0"):
        return 0
    else:
        raise ValueError("invalid truth value %r" % (val,))
