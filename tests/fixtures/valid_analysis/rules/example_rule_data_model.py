def rule(event):
    # filter events on unified data model field
    if event.udm('event_type') and event.udm('event_type') == 'login_failure':
        return True
    # filter based on standard log type's fields
    if event.get('event_type_id', 0) == 6:
        return True
    # unknown event type
    return False


def title(event):
    # use unified data model field in title
    return 'User [{}] from IP [{}] has exceeded the failed logins threshold'.format(
        event.udm('user'), event.udm('source_ip'))
