def rule(event):
    if event.get("operationName") == "Sign-in activity":
        return True
    return False
