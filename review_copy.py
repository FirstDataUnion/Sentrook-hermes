"""Operator-facing review copy for Hermes approve directives.

Hermes only exposes a single ``message`` string on plugin ``approve`` (shown as
Discord/Slack/Telegram **Reason**). The host hardcodes Requested command to
``<tool> (plugin approval rule)``, so the real argv and likely-intent must live
in this one field.

Budget is Discord Reason (300). OpenClaw uses title 80 + description 256; we
mirror description structure (Likely + packed command + hint) without rule IDs
and without forcing a title/description split.
"""

from __future__ import annotations

import re
from typing import Any

from .planir import EXEC_TOOLS
from .sanitize import pack_signal_excerpt, scrub_secrets

# Discord clips Reason at 300; Slack allows 500. Prefer Discord so we never
# silently lose the tail of a carefully packed message there.
REVIEW_MESSAGE_MAX = 300

TRUNCATED_TOKEN = "[TRUNCATED]"
HINT = "Allow once to run it, or deny to stop the agent."
MIN_COMMAND_CHARS = 16

_ID_LINE_RE = re.compile(r"^\([A-Za-z0-9,.\s-]+\)$")


def pending_display_command(args: dict[str, Any] | None) -> str | None:
    if not args:
        return None
    for key in ("command", "cmd", "code"):
        value = args.get(key)
        if not isinstance(value, str):
            continue
        text = value.strip()
        if text and text != TRUNCATED_TOKEN:
            return text
    return None


def _clip(text: str, limit: int) -> str:
    trimmed = text.strip()
    if len(trimmed) <= limit:
        return trimmed
    if limit <= 3:
        return trimmed[:limit]
    return f"{trimmed[: limit - 3]}..."


def _strip_rule_id_lines(text: str) -> str:
    """Drop parenthetical AIRA/rule-id lines — meaningless to operators."""
    kept: list[str] = []
    for line in text.split("\n"):
        if _ID_LINE_RE.match(line.strip()):
            continue
        kept.append(line)
    return "\n".join(kept).strip()


def _likely_line(scan_description: str | None, pending_tool: str) -> str:
    first = (scan_description or "").split("\n")[0].strip() if scan_description else ""
    if (
        first.lower().startswith("likely:")
        and TRUNCATED_TOKEN not in first
    ):
        return first
    if pending_tool in EXEC_TOOLS:
        return "Likely: run a shell command"
    return f"Likely: use the {pending_tool} tool"


def _assemble(likely: str, prefix: str, excerpt: str, *, with_hint: bool) -> str:
    lines = [likely, f"{prefix}`{excerpt}`"]
    if with_hint:
        lines.append(HINT)
    return "\n".join(lines)


def build_review_message(
    *,
    pending_tool: str,
    pending_args: dict[str, Any] | None = None,
    scan_summary: str | None = None,
    scan_description: str | None = None,
    max_len: int = REVIEW_MESSAGE_MAX,
) -> str:
    """Build Hermes ``message`` (Reason body) for an approve card.

    When local argv is available, rebuild like OpenClaw: keep hosted Likely
    when present, pack a signal-aware command excerpt into the remaining
    budget, drop the allow/deny hint if needed. Never include rule ids.
    """
    local_command = pending_display_command(pending_args)
    if local_command:
        scrubbed = scrub_secrets(local_command)
        likely = _likely_line(scan_description, pending_tool)
        prefix = "run: " if pending_tool in EXEC_TOOLS else f"`{pending_tool}`: "

        description = ""
        for with_hint in (True, False):
            fixed = len(likely) + 1 + len(prefix) + 2 + 1  # backticks + newlines
            if with_hint:
                fixed += len(HINT) + 1
            budget = max(MIN_COMMAND_CHARS, max_len - fixed)
            excerpt = pack_signal_excerpt(scrubbed, budget)
            body = _assemble(likely, prefix, excerpt, with_hint=with_hint)
            if len(body) <= max_len:
                description = body
                break
            overflow = len(body) - max_len
            excerpt = pack_signal_excerpt(
                scrubbed, max(budget - overflow - 3, MIN_COMMAND_CHARS)
            )
            body = _assemble(likely, prefix, excerpt, with_hint=with_hint)
            if len(body) <= max_len:
                description = body
                break

        if not description:
            description = _clip(likely, max_len)
        return _clip(description, max_len)

    for candidate in (scan_description, scan_summary):
        if isinstance(candidate, str) and candidate.strip():
            body = _strip_rule_id_lines(candidate.strip())
            if not body:
                continue
            if not body.lower().startswith("sentrook") and not body.lower().startswith(
                "likely:"
            ):
                body = f"Sentrook: {body}"
            return _clip(body, max_len)

    return _clip(
        scan_summary or "Sentrook flagged this tool call for human review",
        max_len,
    )
