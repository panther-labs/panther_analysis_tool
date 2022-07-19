import argparse


def for_public_api(parser: argparse.ArgumentParser, required: bool) -> None:
    parser.add_argument("--api-token",
                        type=str,
                        help="The Panther API token to use.",
                        required=required)

    parser.add_argument("--api-host",
                        type=str,
                        help="The Panther API token to use.",
                        required=required)


def using_aws_profile(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--aws-profile",
                        type=str,
                        help="The AWS profile to use when updating the AWS Panther deployment.",
                        required=False)
