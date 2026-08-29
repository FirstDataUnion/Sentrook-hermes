"""Granular Hermes rule_key for once/session/always approval grain."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .planir import EXEC_TOOLS, PlanIR, canonicalize_tool_args, last_pending_step
from .review_copy import pending_display_command

RULE_KEY_PREFIX = "sentrook"
DIGEST_HEX_CHARS = 16


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stable_args_text(args: dict[str, Any]) -> str:
    keys = sorted(args)
    parts: list[str] = []
    for key in keys:
        value = args[key]
        if isinstance(value, str):
            parts.append(f"{key}={value}")
        elif isinstance(value, (int, float, bool)):
            parts.append(f"{key}={value}")
    return " ".join(parts)


def build_rule_key(
    plan: PlanIR,
    *,
    pending_args: dict[str, Any] | None = None,
    kind_override: str | None = None,
    fingerprint_override: str | None = None,
) -> str:
    """Return ``sentrook:<kind>:<digest>`` for Hermes approval persistence."""
    if kind_override and fingerprint_override:
        digest = _sha256_hex(fingerprint_override)[:DIGEST_HEX_CHARS]
        return f"{RULE_KEY_PREFIX}:{kind_override}:{digest}"

    pending = last_pending_step(plan)
    tool = pending.tool if pending else "unknown"
    args = pending_args or (pending.args if pending else {})

    if tool in EXEC_TOOLS:
        command = pending_display_command(args)
        if command:
            digest = _sha256_hex(command.strip())[:DIGEST_HEX_CHARS]
            return f"{RULE_KEY_PREFIX}:exec:{digest}"

    canonical = canonicalize_tool_args(tool, args)
    fingerprint = json.dumps(
        {"tool": tool, "args": canonical}, sort_keys=True, separators=(",", ":")
    )
    digest = _sha256_hex(fingerprint)[:DIGEST_HEX_CHARS]
    kind = tool if tool else "tool"
    return f"{RULE_KEY_PREFIX}:{kind}:{digest}"


def build_scan_error_rule_key(
    failure_kind: str,
    *,
    tool: str | None = None,
    pending_args: dict[str, Any] | None = None,
) -> str:
    """Fingerprint failure kind plus the pending tool so Always Allow cannot
    skip later timeouts of unrelated commands.
    """
    canonical = canonicalize_tool_args(tool or "", pending_args or {})
    fingerprint = json.dumps(
        {"kind": failure_kind, "tool": tool or "", "args": canonical},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = _sha256_hex(fingerprint)[:DIGEST_HEX_CHARS]
    return f"{RULE_KEY_PREFIX}:scan_error:{digest}"
