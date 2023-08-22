IGNORED_USERS = {}


def policy(resource):
    if resource["UserName"] in IGNORED_USERS:
        return False

    cred_report = resource.get("CredentialReport", {})
    if not cred_report:
        return True

    return cred_report.get("PasswordEnabled", False) and cred_report.get("MfaActive", False)


def title(resource):
    return "THIS IS AN EXAMPLE TITLE"


def alert_context(resource):
    return {"ip": "1.1.1.1"}


def description(resource):
    return "THIS IS AN EXAMPLE DESCRIPTION."


def destinations(resource):
    return ["ExampleDestinationName"]


def runbook(resource):
    return "THIS IS AN EXAMPLE RUNBOOK VALUE."


def reference(resource):
    return "THIS IS AN EXAMPLE REFERENCE."


def severity(resource):
    return "CrItIcAl"
