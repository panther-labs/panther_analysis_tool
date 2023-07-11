from dataclasses import dataclass


@dataclass
class FakeDestination:
    """Stub class as a replacement for the Destination class
    that wraps alert output metadata."""

    destination_id: str
    destination_display_name: str
