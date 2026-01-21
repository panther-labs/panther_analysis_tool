import ast
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
    inverted: bool = False


# Parses the filters, expects a list of strings
def parse_filter_args(str_filters: Optional[List[str]]) -> Tuple[List[Filter], List[Filter]]:
    parsed_filters: Dict[str, Any] = {}
    parsed_filters_inverted: Dict[str, Any] = {}
    if str_filters is None:
        return [], []
    for filt in str_filters:
        split = filt.split("=")
        if len(split) != 2 or split[0] == "" or split[1] == "":
            raise ValueError(f"Filter {filt} is not in format KEY=VALUE")
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
            raise ValueError(f"Filter key {key} is not a valid filter field")
        if invert_filter:
            parsed_filters_inverted[key] = split[1].split(",")
        else:
            parsed_filters[key] = split[1].split(",")
        # Handle boolean fields
        if key == "Enabled":
            try:
                bool_value = bool(strtobool(split[1]))
            except ValueError:
                raise ValueError(f"Filter key {key} should have either true or false")
            if invert_filter:
                parsed_filters_inverted[key] = [bool_value]
            else:
                parsed_filters[key] = [bool_value]

    filters = [Filter(key=key, values=values) for key, values in parsed_filters.items()]
    filters_inverted = [
        Filter(key=key, values=values, inverted=True)
        for key, values in parsed_filters_inverted.items()
    ]
    return filters, filters_inverted


def get_filters_with_status_filters(
    str_filters: Optional[List[str]],
) -> Tuple[List[Filter], List[Filter]]:
    filters, filters_inverted = parse_filter_args(str_filters)
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
    filters_inverted.append(
        Filter(key="Status", values=[EXPERIMENTAL_STATUS, DEPRECATED_STATUS], inverted=True)
    )
    return filters, filters_inverted


def strtobool(val: str) -> int:
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return 1
    elif val in ("n", "no", "f", "false", "off", "0"):
        return 0
    else:
        raise ValueError("invalid truth value %r" % (val,))


def collect_top_level_imports(py: bytes) -> set[str]:
    """
    Collects all imports from a Python file by parsing the file is an AST
    and extracting the top level imports.

    Example:
    ```python
        from top import foo
        import bar
        import baz.qux
        from baz.qux import quux
        from scoob.qux import quux as quuux
    ```

    Outputs:
    ```python
        {"top", "bar", "baz", "scoob"}
    ```

    Args:
        py: The Python file to parse.

    Returns:
        A set of top level imports.
    """
    try:
        tree = ast.parse(py.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError):
        return set()

    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])

    return imports


def split_search_term(search_term: str) -> list[str]:
    """
    Split a search term by spaces, preserving quoted strings as single tokens.
    Handles nested quotes (e.g., "text 'inner' more" or 'text "inner" more').
    Supports escaped quotes (e.g., "text \\"inner\\" more" or 'text \\'inner\\' more').

    Args:
        search_term: The search term to split

    Returns:
        List of tokens, with quoted strings preserved as single tokens
    """
    if not search_term:
        return []

    tokens: list[str] = []
    current_token: list[str] = []
    in_quotes: str | None = None  # Track which quote type we're inside: '"' or "'"
    escaped = False  # Track if the next character is escaped

    for char in search_term:
        if escaped:
            # Previous character was a backslash
            if char in ('"', "'"):
                # Escaped quote - treat as literal character, don't use as delimiter
                # Keep both backslash and quote
                current_token.append("\\")
                current_token.append(char)
            else:
                # Escaped non-quote character - keep both backslash and character
                current_token.append("\\")
                current_token.append(char)
            escaped = False
        elif char == "\\":
            # Escape character - mark next character as escaped
            escaped = True
            # Don't append backslash yet - we'll handle it when we see the next char
        elif char in ('"', "'"):
            # Only treat as delimiter if not escaped (escaped case handled above)
            if in_quotes == char:
                in_quotes = None  # Closing quote
            elif in_quotes is None:
                in_quotes = char  # Opening quote
            current_token.append(char)
        elif char == " " and in_quotes is None:
            # Space outside quotes - split here
            if current_token:
                tokens.append("".join(current_token))
                current_token = []
        else:
            # Regular character (or space inside quotes)
            current_token.append(char)

    # Handle trailing backslash (not followed by a character)
    if escaped:
        current_token.append("\\")

    if current_token:
        tokens.append("".join(current_token))

    # Remove surrounding quotes and filter empty tokens
    result: list[str] = []
    for token in tokens:
        stripped = token.strip()
        if not stripped:
            continue
        # Remove surrounding quotes if present
        # Check if token starts and ends with matching quotes
        if len(stripped) >= 2:
            first_char = stripped[0]
            last_char = stripped[-1]
            # Only remove quotes if they match and the last quote is not escaped
            if (
                first_char == last_char
                and first_char in ('"', "'")
                and not (len(stripped) >= 2 and stripped[-2] == "\\")
            ):
                stripped = stripped[1:-1]

        # Remove escape sequences: convert \" to " and \' to '
        # But preserve \\ (escaped backslash)
        processed = []
        i = 0
        while i < len(stripped):
            if stripped[i] == "\\" and i + 1 < len(stripped):
                next_char = stripped[i + 1]
                if next_char in ('"', "'"):
                    # Escaped quote - remove backslash, keep quote
                    processed.append(next_char)
                    i += 2
                elif next_char == "\\":
                    # Escaped backslash - keep one backslash
                    processed.append("\\")
                    i += 2
                else:
                    # Escaped other character - keep both
                    processed.append(stripped[i])
                    i += 1
            else:
                processed.append(stripped[i])
                i += 1

        result.append("".join(processed))

    return result


def search_terms_to_filters(search_terms: list[str]) -> list[Filter]:
    result: list[Filter] = []

    for search_term in search_terms:
        if search_term.strip() == "":
            continue

        try:
            filters, filters_inverted = parse_filter_args([search_term])
            result.extend(filters)
            result.extend(filters_inverted)
        except ValueError:
            result.append(Filter(key="", values=[search_term]))

    return result
