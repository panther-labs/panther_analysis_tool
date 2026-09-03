def rule(_event):
    return True


def destinations(event):
    if event.get("route_to_multiple_destinations", False):
        return ["secondary-destination", "test-destination"]
    if event.get("route_alert", False):
        return ["test-destination"]
    return []
