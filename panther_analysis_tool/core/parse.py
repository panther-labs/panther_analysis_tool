import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from panther_analysis_tool.schemas import (
    GLOBAL_SCHEMA,
    POLICY_SCHEMA,
    RULE_SCHEMA,
    extract_keys_schema,
)

EXPERIMENTAL_STATUS = "experimental"
DEPRECATED_STATUS = "deprecated"


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


def get_filters_with_status_filters(
    str_filters: Optional[List[str]],
) -> Tuple[List[Filter], List[Filter]]:
    filters, filters_inverted = parse_filter(str_filters)
    filters, filters_inverted = add_status_filters(filters, filters_inverted)
    return filters, filters_inverted


def add_status_filters(
    filters: List[Filter], filters_inverted: List[Filter]
) -> Tuple[List[Filter], List[Filter]]:
    # check that no existing filter references the status field
    # if found, return them as-is:
    for filt in filters:
        if filt.key == "Status":
            return filters, filters_inverted
    for filt in filters_inverted:
        if filt.key == "Status":
            return filters, filters_inverted
    # otherwise, add an invert filter to filter out any status field
    # with Status: deprecated or Status: experimental
    filters_inverted.append(Filter(key="Status", values=[EXPERIMENTAL_STATUS, DEPRECATED_STATUS]))
    return filters, filters_inverted


def strtobool(val: str) -> int:
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return 1
    elif val in ("n", "no", "f", "false", "off", "0"):
        return 0
    else:
        raise ValueError("invalid truth value %r" % (val,))
