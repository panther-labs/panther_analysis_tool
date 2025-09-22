from typing import Annotated, List, Optional, TypeAlias

import typer

API_DOCUMENTATION = "https://docs.panther.com/api-beta"


APITokenType: TypeAlias = Annotated[
    Optional[str],
    typer.Option(
        envvar="PANTHER_API_TOKEN",
        help=f"The Panther API token to use. See: {API_DOCUMENTATION}",
    ),
]

APIHostType: TypeAlias = Annotated[
    str,
    typer.Option(
        envvar="PANTHER_API_HOST",
        help=f"The Panther API host to use. See: {API_DOCUMENTATION}",
    ),
]

AWSProfileType: TypeAlias = Annotated[
    Optional[str],
    typer.Option(
        envvar="PANTHER_AWS_PROFILE",
        help="The AWS profile to use when updating the AWS Panther deployment.",
    ),
]

FilterType: TypeAlias = Annotated[
    Optional[List[str]],
    typer.Option(
        "--filter",
        envvar="PANTHER_FILTER",
        metavar="KEY=VALUE",
        help="key=value or key!=value pairs used to filter detections. "
        "Repeat the flag to define more than one filter, which will be combined with an AND operator.",
    ),
]

KMSKeyType: TypeAlias = Annotated[
    str,
    typer.Option(envvar="PANTHER_KMS_KEY", help="The key id to use to sign the release asset."),
]

MinimumTestsType: TypeAlias = Annotated[
    int,
    typer.Option(
        envvar="PANTHER_MINIMUM_TESTS",
        help=(
            "The minimum number of tests in order for a detection to be considered passing. "
            "If a number greater than 1 is specified, at least one True and one False test is "
            "required."
        ),
    ),
]

OutType: TypeAlias = Annotated[
    str,
    typer.Option(
        envvar="PANTHER_OUT",
        help="The path to store output files.",
    ),
]

PathType: TypeAlias = Annotated[
    str,
    typer.Option(envvar="PANTHER_PATH", help="The relative path to Panther policies and rules."),
]

SkipTestsType: TypeAlias = Annotated[
    bool, typer.Option(envvar="PANTHER_SKIP_TESTS", help="Skip all tests")
]

SkipDisabledTestsType: TypeAlias = Annotated[
    bool, typer.Option(envvar="PANTHER_SKIP_DISABLED_TESTS", help="Skip disabled tests.")
]

IgnoreExtraKeysType: TypeAlias = Annotated[
    bool,
    typer.Option(
        help="Meant for advanced users; allows skipping of extra keys from schema validation."
    ),
]

IgnoreFilesType: TypeAlias = Annotated[
    Optional[List[str]],
    typer.Option(
        envvar="PANTHER_IGNORE_FILES",
        help="Relative path to files to be ignored. Repeat the flag to define more than one file.",
    ),
]

AvailableDestinationType: TypeAlias = Annotated[
    Optional[List[str]],
    typer.Option(
        envvar="PANTHER_AVAILABLE_DESTINATION",
        help=(
            "A destination name that may be returned by the destinations function. "
            "Repeat the flag to define more than one destination."
        ),
    ),
]

SortTestResultsType: TypeAlias = Annotated[
    bool,
    typer.Option(
        help="Sort test results by whether the test passed or failed (passing tests first), then by rule ID.",
    ),
]

ShowFailuresOnlyType: TypeAlias = Annotated[
    bool, typer.Option(help="Only print test results for failed tests.")
]

IgnoreTableNamesType: TypeAlias = Annotated[
    bool,
    typer.Option(
        help="Allows skipping of table name validation from schema validation. Useful when querying non-Panther or non-Snowflake tables.",
    ),
]

ValidTableNamesType: TypeAlias = Annotated[
    Optional[List[str]],
    typer.Option(
        help=(
            "Fully qualified table names that should be considered valid during schema validation "
            "(in addition to standard Panther/Snowflake tables). "
            "Repeat the flag to define more than one name. "
            "Accepts '*' as wildcard matching 0 or more characters. Example: foo.*bar.baz"
        ),
    ),
]
