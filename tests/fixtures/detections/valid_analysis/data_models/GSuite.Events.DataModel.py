def get_event_type(event):
    for details in event.get("events", []):
        if details.get("type", "") == "login" and details.get("name", "") == "login_failure":
            return "login_failure"
    return "other_event"
