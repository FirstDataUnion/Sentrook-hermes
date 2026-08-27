"""Scan-error policy — Hermes defaults (onScanError review)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

OnScanError = Literal["allow", "deny", "review"]
ScanFailureKind = Literal["rate_limited", "http", "timeout", "network"]

AUTH_STATUSES = frozenset({401, 403})


@dataclass(frozen=True)
class ScanFailure:
    ok: Literal[False]
    kind: ScanFailureKind
    detail: str
    status: int | None = None
    retry_after_sec: float | None = None


@dataclass(frozen=True)
class HermesDirective:
    action: Literal["block", "approve"]
    message: str
    rule_key: str | None = None


def parse_on_scan_error(raw: Any, fallback: OnScanError = "review") -> OnScanError:
    if raw in ("allow", "deny", "review"):
        return raw
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized in ("allow", "deny", "review"):
            return normalized
    return fallback


def resolve_on_scan_error(
    *,
    plugin_config: Any = None,
    env: dict[str, str] | None = None,
) -> OnScanError:
    env = env or dict(os.environ)
    raw = plugin_config if plugin_config is not None else env.get("SENTROOK_ON_SCAN_ERROR")
    return parse_on_scan_error(raw, fallback="review")


def is_scan_failure(value: Any) -> bool:
    return isinstance(value, ScanFailure) and value.ok is False


def is_auth_failure(failure: ScanFailure) -> bool:
    return failure.kind == "http" and failure.status in AUTH_STATUSES


def _detail_snippet(failure: ScanFailure, limit: int = 100) -> str:
    raw = (failure.detail or "").strip().replace("\n", " ")
    if not raw:
        return ""
    if len(raw) <= limit:
        return raw
    return f"{raw[: max(0, limit - 3)]}..."


def scan_error_copy(failure: ScanFailure) -> str:
    """Operator-facing body for interactive scan-error review cards."""
    if failure.kind == "rate_limited":
        return "Sentrook rate-limited this scan. Continue this tool without a security scan?"
    if is_auth_failure(failure):
        return (
            "Sentrook could not authenticate to the scan service "
            "(configuration error — not a security policy block). "
            "Continue this tool without scanning?"
        )
    return "Sentrook is unreachable. Continue without scanning?"


def _block_reason_for(failure: ScanFailure) -> str:
    """Agent-facing block message when the tool must not run."""
    snippet = _detail_snippet(failure)
    if is_auth_failure(failure):
        base = (
            "Sentrook could not authenticate to the scan service "
            "(configuration error, not a security policy deny). "
            "Re-run `hermes sentrook configure` / `verify`, and ensure "
            "SENTROOK_OIDC_ISSUER matches this Sentrook environment. "
            "The tool was not scanned or run."
        )
        return f"{base} Detail: {snippet}" if snippet else base
    if failure.kind == "rate_limited":
        base = "Sentrook rate-limited this scan; the tool was not scanned or run."
        return f"{base} Detail: {snippet}" if snippet else base
    base = (
        "Sentrook did not scan this tool call (unreachable or timed out). "
        "This is a connectivity/service issue, not a security policy deny. "
        "The tool was not run."
    )
    return f"{base} Detail: {snippet}" if snippet else base


def scan_error_to_directive(
    failure: ScanFailure,
    *,
    on_scan_error: OnScanError,
    unattended: bool,
    rule_key: str,
) -> HermesDirective | None:
    """Map a failed /scan attempt to a Hermes pre_tool_call directive.

    Auth failures (401/403) never fail-open: ``on_scan_error=allow`` still
    blocks. ``deny`` and ``review`` follow the same policy as other scan
    errors so operators get a clear config-error card instead of a silent
    hard block that looks like a policy deny.
    """
    if is_auth_failure(failure) and on_scan_error == "allow":
        return HermesDirective(action="block", message=_block_reason_for(failure))

    policy = on_scan_error
    if policy == "allow":
        return None
    if policy == "deny":
        return HermesDirective(action="block", message=_block_reason_for(failure))

    # review
    if unattended:
        return HermesDirective(action="block", message=_block_reason_for(failure))

    return HermesDirective(
        action="approve",
        message=scan_error_copy(failure),
        rule_key=rule_key,
    )


def parse_retry_after_seconds(header: str | None) -> float | None:
    if not header:
        return None
    trimmed = header.strip()
    try:
        as_number = float(trimmed)
        if as_number >= 0:
            return as_number
    except ValueError:
        pass
    try:
        when = datetime.fromisoformat(trimmed.replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        delta = when.timestamp() - datetime.now(UTC).timestamp()
        return max(0.0, delta)
    except ValueError:
        return None
