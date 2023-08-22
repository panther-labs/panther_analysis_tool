from datetime import date
from unittest.mock import MagicMock

import boto3

IGNORED_USERS = {}


def rule(event):
    return all(isinstance(x, MagicMock) for x in [boto3, boto3.client, date])


def title(event):
    return (
        f"BOTO3: {isinstance(boto3, MagicMock)} - "
        f"BOTO3.CLIENT: {isinstance(boto3.client, MagicMock)} - "
        f"DATE: {isinstance(date, MagicMock)}"
    )
