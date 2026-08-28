def rule(_event):
    return True


def destinations(event):
    if event.get("route_alert", False):
        return ["test-destination"]
    return []
