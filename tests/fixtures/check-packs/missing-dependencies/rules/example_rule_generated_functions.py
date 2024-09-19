IGNORED_USERS = {}


def rule(event):
    return True


def title(event):
    return "THIS IS AN EXAMPLE TITLE"


def alert_context(event):
    return {"ip": "1.1.1.1"}


def description(event):
    return "THIS IS AN EXAMPLE DESCRIPTION."


def destinations(event):
    return ["ExampleDestinationName"]


def runbook(event):
    return "THIS IS AN EXAMPLE RUNBOOK VALUE."


def reference(event):
    return "THIS IS AN EXAMPLE REFERENCE."


def severity(event):
    return "CRITICAL"
