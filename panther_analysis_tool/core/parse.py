import logging
from distutils.util import strtobool
from typing import Any, Dict, List, Tuple

from schema import Optional

from panther_analysis_tool.schemas import GLOBAL_SCHEMA, POLICY_SCHEMA, RULE_SCHEMA


# Parses the filters, expects a list of strings
def parse_filter(filters: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    parsed_filters: Dict[str, Any] = {}
    parsed_filters_inverted: Dict[str, Any] = {}
    for filt in filters:
        split = filt.split("=")
        if len(split) != 2 or split[0] == "" or split[1] == "":
            logging.warning("Filter %s is not in format KEY=VALUE, skipping", filt)
            continue
        # Check for "!="
        invert_filter = split[0].endswith("!")
        if invert_filter:
            split[0] = split[0][:-1]  # Remove the trailing "!"
        key = split[0]
        if not any(
            (
                key
                in (
                    list(GLOBAL_SCHEMA.schema.keys())
                    + list(POLICY_SCHEMA.schema.keys())
                    + list(RULE_SCHEMA.schema.keys())
                )
                for key in (key, Optional(key))
            )
        ):
            logging.warning("Filter key %s is not a valid filter field, skipping", key)
            continue
        if invert_filter:
            parsed_filters_inverted[key] = split[1].split(",")
        else:
            parsed_filters[key] = split[1].split(",")
        # Handle boolean fields
        if key == "Enabled":
            try:
                bool_value = bool(strtobool(split[1]))
            except ValueError:
                logging.warning("Filter key %s should have either true or false, skipping", key)
                continue
            if invert_filter:
                parsed_filters_inverted[key] = [bool_value]
            else:
                parsed_filters[key] = [bool_value]
    return parsed_filters, parsed_filters_inverted
