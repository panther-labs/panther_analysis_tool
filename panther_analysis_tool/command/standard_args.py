from typing import Annotated, List, Optional

import typer

API_DOCUMENTATION = "https://docs.panther.com/api-beta"


APITokenT = Annotated[
    Optional[str],
    typer.Option(
        envvar="PANTHER_API_TOKEN",
        help=f"The Panther API token to use. See: {API_DOCUMENTATION}",
    ),
]

APIHostT = Annotated[
    str,
    typer.Option(
        envvar="PANTHER_API_HOST",
        help=f"The Panther API host to use. See: {API_DOCUMENTATION}",
    ),
]

AWSProfileT = Annotated[
    Optional[str],
    typer.Option(
        envvar="PANTHER_AWS_PROFILE",
        help="The AWS profile to use when updating the AWS Panther deployment.",
    ),
]

FilterT = Annotated[
    Optional[List[str]],
    typer.Option(
        "--filter", envvar="PANTHER_FILTER", metavar="KEY=VALUE", help="Filter detections"
    ),
]

KMSKeyT = Annotated[
    Optional[str],
    typer.Option(envvar="PANTHER_KMS_KEY", help="The key id to use to sign the release asset."),
]

MinimumTestsT = Annotated[
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

OutT = Annotated[
    str,
    typer.Option(
        envvar="PANTHER_OUT",
        help="The path to store output files.",
    ),
]

PathT = Annotated[
    str,
    typer.Option(envvar="PANTHER_PATH", help="The relative path to Panther policies and rules."),
]

SkipTestsT = Annotated[bool, typer.Option(envvar="PANTHER_SKIP_TESTS", help="Skip all tests")]

SkipDisabledTestsT = Annotated[
    bool, typer.Option(envvar="PANTHER_SKIP_DISABLED_TESTS", help="Skip disabled tests.")
]

IgnoreExtraKeysT = Annotated[
    bool,
    typer.Option(
        help="Meant for advanced users; allows skipping of extra keys from schema validation."
    ),
]

IgnoreFilesT = Annotated[
    Optional[List[str]],
    typer.Option(
        envvar="PANTHER_IGNORE_FILES",
        help="Relative path to files to be ignored (space separated). Example ./foo.yaml ./bar/baz.yaml",
    ),
]

AvailableDestinationT = Annotated[
    Optional[List[str]],
    typer.Option(
        envvar="PANTHER_AVAILABLE_DESTINATION",
        help=(
            "A destination name that may be returned by the destinations function. "
            "Repeat the argument to define more than one name."
        ),
    ),
]

SortTestResultsT = Annotated[
    bool,
    typer.Option(
        help="Sort test results by whether the test passed or failed (passing tests first), then by rule ID.",
    ),
]

ShowFailuresOnlyT = Annotated[bool, typer.Option(help="Only print test results for failed tests.")]

IgnoreTableNamesT = Annotated[
    bool,
    typer.Option(
        help="Allows skipping of table name validation from schema validation. Useful when querying non-Panther or non-Snowflake tables.",
    ),
]

ValidTableNamesT = Annotated[
    Optional[List[str]],
    typer.Option(
        help=(
            "Fully qualified table names that should be considered valid during schema validation "
            "(in addition to standard Panther/Snowflake tables), space separated. "
            "Accepts '*' as wildcard matching 0 or more characters. Example: foo.bar.baz bar.baz.* foo.*bar.baz baz.* *.foo.*"
        ),
    ),
]
