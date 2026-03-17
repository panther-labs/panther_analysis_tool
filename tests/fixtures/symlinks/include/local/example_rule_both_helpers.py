from symlinks_helper_remote import a_says_hello
from symlinks_local_helper import local_hello


def rule(_event):
    return local_hello() == "local" and a_says_hello() == "remote"
