def rule(event):
    return event.get("suspicious", False)


def unique(event):
    """Returns a unique identifier for aggregating distinct values"""
    return event.get("user_id", "unknown")


def title(event):
    return f"Suspicious activity detected for user: {event.get('user_id', 'unknown')}"
