from a_helper import a_says_hello


def rule(_):
    output = a_says_hello()
    return output == 'hello from b before a says hello'
