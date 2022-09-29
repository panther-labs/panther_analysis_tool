_filters = []


def _deep_equal(event):
    import functools
    import collections
    keys = 'eventType'.split('.')
    actual = functools.reduce(lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None, keys,
                              event)
    return bool(actual == 'system.api_token.create')


_filters.append(_deep_equal)


def _deep_equal(event):
    import functools
    import collections
    keys = 'outcome.result'.split('.')
    actual = functools.reduce(lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None, keys,
                              event)
    return bool(actual == 'SUCCESS')


_filters.append(_deep_equal)


def _execute(event):
    for f in _filters:
        if f(event) == False:
            return False
    return True


_event = {'uuid': '2a992f80-d1ad-4f62-900e-8c68bb72a21b', 'published': '2021-01-08 21:28:34.875',
          'eventType': 'system.api_token.create', 'version': '0', 'severity': 'INFO',
          'legacyEventType': 'api.token.create', 'displayMessage': 'Create API token',
          'actor': {'alternateId': 'user@example.com', 'displayName': 'Test User', 'id': '00u3q14ei6KUOm4Xi2p4',
                    'type': 'User'}, 'outcome': {'result': 'SUCCESS'}, 'request': {}, 'debugContext': {}, 'target': [
        {'id': '00Tpki36zlWjhjQ1u2p4', 'type': 'Token', 'alternateId': 'unknown', 'displayName': 'test_key',
         'details': None}]}

_result = _execute(_event)

print(_result)
