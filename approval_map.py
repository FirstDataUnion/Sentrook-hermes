"""Map Hermes Discord/CLI approval choices onto Sentrook feedback resolutions."""

from __future__ import annotations

from .scan_client import ApprovalResolution


def map_approval_choice(choice: str) -> ApprovalResolution | None:
    normalized = choice.strip().lower()
    mapping: dict[str, ApprovalResolution] = {
        "once": "allow-once",
        "allow-once": "allow-once",
        "allow_once": "allow-once",
        # Hermes "session" is host-local persistence; corpus has no session label.
        "session": "allow-once",
        "always": "allow-always",
        "allow-always": "allow-always",
        "allow_always": "allow-always",
        "deny": "deny",
        "timeout": "timeout",
        "cancelled": "cancelled",
        "cancel": "cancelled",
    }
    return mapping.get(normalized)
