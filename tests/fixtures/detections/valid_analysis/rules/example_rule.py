from panther import test_helper # pylint: disable=import-error

IGNORED_USERS = {}


def rule(event):
    if event['UserName'] in IGNORED_USERS:
        return False

    if 'CredentialReport' not in event:
        return False

    cred_report = event.get('CredentialReport', {})
    if not cred_report:
        return True

    return (test_helper() and
            cred_report.get('PasswordEnabled', False) and
            cred_report.get('MfaActive', False))

def dedup(event):
    return event['UserName']

def title(event):
    return '{} does not have MFA enabled'.format(event['UserName'])


def alert_context(event):
    # test/validate that we can return the event as alert_context
    return event
