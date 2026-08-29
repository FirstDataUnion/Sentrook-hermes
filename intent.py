"""Intent classification for Hermes sessions."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from typing import Any

from .planir import IntentKind

CRON_MARKER = re.compile(r"^\s*\[cron:", re.IGNORECASE)
SUBAGENT_MARKER = re.compile(r"\[Subagent Context\]|\[Subagent Task\]", re.IGNORECASE)
SYSTEM_MARKER = re.compile(r"^\s*\[system[:\]]", re.IGNORECASE)


@dataclass
class RunIntent:
    intent: str
    kind: IntentKind


def classify_intent(text: str) -> IntentKind:
    normalized = text.strip()
    if CRON_MARKER.search(normalized):
        return "cron"
    if SUBAGENT_MARKER.search(normalized):
        return "subagent"
    if SYSTEM_MARKER.search(normalized):
        return "system"
    return "user"


def is_cron_env(env: dict[str, str] | None = None) -> bool:
    env = env or dict(os.environ)
    return env.get("HERMES_CRON_SESSION", "").strip().lower() in {"1", "true", "yes"}


def is_non_tty() -> bool:
    try:
        return not sys.stdin.isatty()
    except Exception:
        return False


# Gateway / chat surfaces have a human in-band even when stdin is not a TTY.
# Treating non-TTY alone as unattended wrongly escalates review→block on any
# chat gateway (Discord, Telegram, Slack, Feishu, …) instead of an approve card.
# ``webhook`` and ``homeassistant`` are omitted — they often have no approval UI,
# so non-TTY on those platforms stays unattended (block on review).
ATTENDED_PLATFORMS = frozenset(
    {
        "discord",
        "telegram",
        "slack",
        "whatsapp",
        "signal",
        "matrix",
        "sms",
        "email",
        "web",
        "feishu",
        "lark",
        "yuanbao",
        "dingtalk",
        "wecom",
        "mattermost",
    }
)


def _hermes_session_platform() -> str:
    """Read platform from Hermes task-local session context (not process env).

    Gateway ≥0.18 stores ``HERMES_SESSION_PLATFORM`` in a ContextVar so concurrent
    Discord/Telegram turns do not clobber each other. ``os.environ`` alone is
    wrong on the gateway path — ``pre_tool_call`` also does not pass ``platform``.
    """
    try:
        from gateway.session_context import get_session_env

        value = get_session_env("HERMES_SESSION_PLATFORM", "")
        if isinstance(value, str) and value.strip():
            return value.strip()
    except Exception:
        pass
    return ""


def resolve_session_platform(
    platform: str | None = None,
    *,
    env: dict[str, str] | None = None,
) -> str | None:
    """Best-effort session platform for attended/unattended decisions."""
    if isinstance(platform, str) and platform.strip():
        return platform.strip()
    from_ctx = _hermes_session_platform()
    if from_ctx:
        return from_ctx
    env = env or dict(os.environ)
    for key in ("HERMES_SESSION_PLATFORM", "HERMES_PLATFORM"):
        value = env.get(key, "")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


# Platforms that must never escalate Sentrook review (no reliable human gate).
UNATTENDED_PLATFORMS = frozenset({"cron", "subagent"})


def is_hermes_approval_bypass(*, env: dict[str, str] | None = None) -> bool:
    """True when Hermes would auto-approve plugin ``approve`` directives.

    Covers ``--yolo`` / ``HERMES_YOLO_MODE``, session ``/yolo``, and
    ``approvals.mode: off``. Under those modes Sentrook ``review`` must not
    escalate (Hermes would silently approve); we block instead.
    """
    try:
        from tools.approval import is_approval_bypass_active

        if is_approval_bypass_active():
            return True
    except Exception:
        pass
    env = env or dict(os.environ)
    return env.get("HERMES_YOLO_MODE", "").strip().lower() in {"1", "true", "yes", "on"}


def is_unattended(
    *,
    env: dict[str, str] | None = None,
    platform: str | None = None,
    subagent: bool = False,
) -> bool:
    """Headless contexts where review must not escalate.

    Unattended: cron, subagent, approval-bypass (YOLO / mode=off), or non-TTY
    CLI without a chat platform.
    Attended: known chat/gateway platforms (via ContextVar or explicit
    ``platform``), or an interactive TTY.
    """
    env = env or dict(os.environ)
    if is_cron_env(env):
        return True
    if is_hermes_approval_bypass(env=env):
        return True
    plat = (resolve_session_platform(platform, env=env) or "").strip().lower()
    if plat in UNATTENDED_PLATFORMS:
        return True
    if subagent:
        return True
    if plat in ATTENDED_PLATFORMS:
        return False
    if is_non_tty():
        return True
    return False


def resolve_intent_kind(
    intent_kind: IntentKind | None,
    intent: str | None,
    *,
    env: dict[str, str] | None = None,
    platform: str | None = None,
    subagent: bool = False,
) -> IntentKind:
    if subagent:
        return "subagent"
    plat = (resolve_session_platform(platform, env=env) or "").strip().lower()
    if plat == "subagent":
        return "subagent"
    if is_cron_env(env) or plat == "cron":
        return "cron"
    if intent_kind:
        return intent_kind
    if intent and intent.strip():
        return classify_intent(intent)
    return "user"


def extract_prompt_text(**kwargs: Any) -> str | None:
    for key in ("prompt", "user_message", "message", "content", "text"):
        value = kwargs.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None
