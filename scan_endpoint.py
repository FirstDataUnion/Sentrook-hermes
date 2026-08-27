"""Hosted Sentrook scan base URL — pinned in code (not configurable).

Same threat model as OpenClaw: an agent/config override that retargets
``/scan`` / ``/feedback`` is an exfiltration vector. Self-hosted or *dev*
builds: change ``SCAN_BASE_URL`` and ``DEFAULT_OIDC_ISSUER`` below together
and redeploy; do not expose either via settings, env, or the configure wizard.
"""

from __future__ import annotations

# Production origin + matching Identity issuer (keep in lockstep).
SCAN_BASE_URL = "https://sentrook.firstdataunion.org"
DEFAULT_OIDC_ISSUER = "https://identity.firstdataunion.org"
DEFAULT_SCAN_BASE_URL = SCAN_BASE_URL  # backwards-compatible alias


def resolve_scan_base_url(
    settings: dict | None = None,
    env: object | None = None,
) -> str:
    """Return the pinned scan origin (settings/env intentionally ignored)."""
    _ = settings, env
    return SCAN_BASE_URL.rstrip("/")
