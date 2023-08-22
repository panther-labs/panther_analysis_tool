from datetime import date

import boto3

IGNORED_USERS = {}


def rule(event):
    return True
