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

import json
import re
from typing import Any

from .planir import EXEC_COMMAND_ALIASES, EXEC_TOOLS, stringify_arg_value
from .sanitize import pack_signal_excerpt, scrub_secrets

# Discord clips Reason at 300; Slack allows 500. Prefer Discord so we never
# silently lose the tail of a carefully packed message there.
REVIEW_MESSAGE_MAX = 300

TRUNCATED_TOKEN = "[TRUNCATED]"
HINT = "Allow once to run it, or deny to stop the agent."
MIN_COMMAND_CHARS = 16
_PAYLOAD_COLLAPSE_MIN = 48
_PAYLOAD_PREVIEW = 40
_EXEC_COMMAND_KEYS = ("command",) + EXEC_COMMAND_ALIASES
_BODY_FLAGS = frozenset(
    {
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "--data-ascii",
        "-F",
        "--form",
        "-m",
        "--message",
        "--content",
        "--body",
        "--json",
        "--payload",
    }
)
_URL_RE = re.compile(r"https?://", re.IGNORECASE)

_ID_LINE_RE = re.compile(r"^\([A-Za-z0-9,.\s-]+\)$")


def pending_display_command(args: dict[str, Any] | None) -> str | None:
    if not args:
        return None
    for key in _EXEC_COMMAND_KEYS:
        if key not in args:
            continue
        text = stringify_arg_value(args[key]).strip()
        if text and text != TRUNCATED_TOKEN:
            return text
    return None


def _collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def _looks_like_url_or_path(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if stripped.startswith(("@", "/", "~")):
        return True
    return bool(_URL_RE.match(stripped))


def _payload_stub(body: str, quote: str) -> str:
    """Short stand-in for a long quoted payload; keep a content/text preview when JSON."""
    stripped = body.strip()
    preview = "…"
    try:
        data = json.loads(stripped)
    except (json.JSONDecodeError, TypeError, ValueError):
        data = None
    if isinstance(data, dict):
        preview = "{…}"
        for key in ("content", "text", "body", "message", "caption"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                shown = _collapse_ws(value).replace(quote, "")
                if len(shown) > _PAYLOAD_PREVIEW:
                    shown = shown[: _PAYLOAD_PREVIEW - 1] + "…"
                preview = f"{{{key}: {shown}}}"
                break
    elif isinstance(data, list):
        preview = "[…]"
    return f"{quote}{preview}{quote}"


def _should_collapse_payload(previous_token: str, body: str) -> bool:
    if len(body) < _PAYLOAD_COLLAPSE_MIN:
        return False
    if _looks_like_url_or_path(body):
        return False
    flag = previous_token.split("=", 1)[0].lower()
    if flag in _BODY_FLAGS:
        return True
    stripped = body.strip()
    return stripped.startswith("{") or stripped.startswith("[")


def collapse_long_payloads(command: str) -> str:
    """Replace long quoted JSON/message bodies; keep URLs, paths, and destinations.

    Linear scan (no nested quote regex) so long payloads cannot trip ReDoS.
    Same treatment as OpenClaw ``reviewCopy.ts`` / hosted review copy.
    """
    out: list[str] = []
    i = 0
    n = len(command)
    prev_token = ""
    token: list[str] = []

    def flush_token() -> None:
        nonlocal prev_token
        if token:
            prev_token = "".join(token)
            token.clear()

    while i < n:
        ch = command[i]
        if ch in "'\"":
            quote = ch
            i += 1
            body_chars: list[str] = []
            while i < n:
                cur = command[i]
                if cur == "\\" and i + 1 < n:
                    body_chars.append(cur)
                    body_chars.append(command[i + 1])
                    i += 2
                    continue
                if cur == quote:
                    i += 1
                    break
                body_chars.append(cur)
                i += 1
            body = "".join(body_chars)
            if _should_collapse_payload(prev_token, body):
                out.append(_payload_stub(body, quote))
            else:
                out.append(f"{quote}{body}{quote}")
            prev_token = ""
            token.clear()
            continue
        if ch.isspace() or ch in ";|&":
            flush_token()
            out.append(ch)
            i += 1
            continue
        token.append(ch)
        out.append(ch)
        i += 1
    return "".join(out)


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
        scrubbed = collapse_long_payloads(scrub_secrets(local_command))
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
