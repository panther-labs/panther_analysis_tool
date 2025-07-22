def rule(event):
    """Test rule that deliberately raises an exception for debug testing."""
    # This rule intentionally raises an exception to test debug traceback functionality
    sub_func()

def sub_func():
    raise ValueError('Test exception for debug tracing')