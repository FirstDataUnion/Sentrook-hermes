"""Maintainer-only local JSONL diagnostic log.

Off by default. Not in plugin.yaml, the configure wizard, or the public README.
Enable with SENTROOK_DEV_LOG=1 in process env or ~/.hermes/.env; optional
SENTROOK_DEV_LOG_PATH overrides the default ($HERMES_STATE_DIR/sentrook-dev.log).

Records local pending argv, scrubbed egress PlanIR, hosted scan decisions, and
the Hermes approve Reason actually shown — so a bad card or a surprising review
can be compared against the corpus without reconstructing the hook from agent.log.

Secrets/PII are pattern-scrubbed (same rules as review copy / PlanIR egress).
The file is still sensitive: chmod 600, treat like config.yaml. Never logs OIDC
tokens or scan credentials. Failures never affect the hook.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from .auth import env_with_hermes_dotenv, resolve_hermes_state_dir
from .planir import PlanIR, last_pending_step, planir_to_dict
from .review_copy import (
    REVIEW_MESSAGE_MAX,
    build_review_message,
    pending_display_command,
    review_copy_source,
)
from .sanitize import maybe_sanitize_planir, scrub_secrets
from .scan_client import ScanResponse, ScanTiming
from .scan_error_policy import ScanFailure

logger = logging.getLogger("sentrook")

DEV_LOG_SCHEMA = "sentrook.plugin.devlog/v1"
DEFAULT_DEV_LOG_NAME = "sentrook-dev.log"
DEV_LOG_MAX_BYTES = 8 * 1024 * 1024
DEV_LOG_STRING_MAX = 8_000
DEV_LOG_INTENT_MAX = 2_000

DevLogEventName = Literal[
    "register",
    "scan",
    "scan_error",
    "resolution",
    "action",
    "plugin_error",
]


@dataclass(frozen=True)
class DevLogConfig:
    enabled: bool
    path: Path


def _parse_enabled(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    if not isinstance(raw, str):
        return False
    return raw.strip().lower() in ("1", "true", "yes", "on")


def resolve_dev_log_config(env: dict[str, str] | None = None) -> DevLogConfig:
    """Resolve from an already-merged env map, or ~/.hermes/.env when ``env`` is None."""
    merged = env_with_hermes_dotenv() if env is None else dict(env)
    enabled = _parse_enabled(merged.get("SENTROOK_DEV_LOG"))
    override = (merged.get("SENTROOK_DEV_LOG_PATH") or "").strip()
    if override:
        path = Path(override).expanduser().resolve()
    else:
        path = (resolve_hermes_state_dir(merged) / DEFAULT_DEV_LOG_NAME).resolve()
    return DevLogConfig(enabled=enabled, path=path)


def scrub_dev_text(text: str, max_chars: int = DEV_LOG_STRING_MAX) -> str:
    scrubbed = scrub_secrets(text)
    if len(scrubbed) <= max_chars:
        return scrubbed
    return f"{scrubbed[: max_chars - 3]}..."


def scrub_dev_value(value: Any, depth: int = 0) -> Any:
    if value is None:
        return value
    if depth > 8:
        return "[…]"
    if isinstance(value, str):
        return scrub_dev_text(value)
    if isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, list):
        return [scrub_dev_value(item, depth + 1) for item in value[:40]]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for i, (key, child) in enumerate(value.items()):
            if i >= 40:
                break
            out[str(key)] = scrub_dev_value(child, depth + 1)
        return out
    return str(value)


def _pending_command_from_args(args: dict[str, Any] | None) -> str | None:
    if not args:
        return None
    return pending_display_command(args)


def _pending_command_from_plan_dict(plan: dict[str, Any] | None) -> str | None:
    if not plan:
        return None
    steps = plan.get("steps")
    if not isinstance(steps, list):
        return None
    for step in reversed(steps):
        if isinstance(step, dict) and step.get("status") == "pending":
            args = step.get("args")
            if isinstance(args, dict):
                return _pending_command_from_args(args)
    return None


def _rotate_if_needed(path: Path) -> None:
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size < DEV_LOG_MAX_BYTES:
        return
    bak = path.with_name(path.name + ".1")
    try:
        bak.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        path.replace(bak)
    except OSError:
        pass


def append_dev_log(config: DevLogConfig, event: dict[str, Any]) -> None:
    if not config.enabled:
        return
    path = config.path
    if not path.is_absolute():
        return
    record = {
        "ts": event.get("ts") or datetime.now(UTC).isoformat(),
        "schema_version": DEV_LOG_SCHEMA,
        **{k: v for k, v in event.items() if k not in ("ts", "schema_version")},
    }
    try:
        line = json.dumps(record, ensure_ascii=False) + "\n"
    except (TypeError, ValueError) as err:
        logger.warning("dev log serialize failed: %s", err)
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _rotate_if_needed(path)
        created = not path.exists()
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
        if created:
            try:
                path.chmod(0o600)
            except OSError:
                pass
    except OSError as err:
        logger.warning("dev log write failed: %s", err)


def _hook_outcome(mapped: dict[str, Any] | None) -> dict[str, Any]:
    action = mapped.get("action") if mapped else None
    return {
        "action": action,
        "block": action == "block",
        "approve": action == "approve",
    }


def build_scan_dev_event(
    *,
    plan: PlanIR,
    pending_args: dict[str, Any] | None,
    scan: ScanResponse,
    timing: ScanTiming,
    mapped: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pending = last_pending_step(plan)
    pending_tool = (pending.tool if pending else None) or scan.pending_tool or "unknown"
    local_raw = _pending_command_from_args(pending_args)
    outbound = maybe_sanitize_planir(planir_to_dict(plan)).plan
    egress_command = _pending_command_from_plan_dict(outbound)

    card: dict[str, Any] | None = None
    if scan.decision == "review" and mapped and mapped.get("action") == "approve":
        message = str(mapped.get("message") or "")
        source, command_found = review_copy_source(
            pending_args=pending_args,
            scan_summary=scan.summary,
            scan_description=scan.review_description,
        )
        if not message:
            message = build_review_message(
                pending_tool=pending_tool,
                pending_args=pending_args,
                scan_summary=scan.summary,
                scan_description=scan.review_description,
            )
        card = {
            "message": message,
            "source": source,
            "command_found": command_found,
            "message_chars": len(message),
            "message_max": REVIEW_MESSAGE_MAX,
        }

    return {
        "event": "scan",
        "session_id": plan.metadata.session_id,
        "run_id": plan.run_id,
        "tool_call_id": plan.metadata.tool_call_id,
        "agent_id": plan.metadata.agent_id,
        "step_seq": plan.metadata.step_seq,
        "intent_kind": plan.intent_kind,
        "intent": scrub_dev_text(plan.intent, DEV_LOG_INTENT_MAX) if plan.intent else None,
        "tool": pending_tool,
        "local": {
            "args": scrub_dev_value(pending_args or (pending.args if pending else {})),
            "command": scrub_dev_text(local_raw) if local_raw else None,
            "command_chars": len(local_raw) if local_raw else 0,
        },
        "egress": {
            "pending_command": scrub_dev_text(egress_command) if egress_command else None,
            "pending_command_chars": len(egress_command) if egress_command else 0,
            "truncated": bool(local_raw) and bool(egress_command) and local_raw != egress_command,
            "sanitize_ms": timing.sanitize_ms,
        },
        "scan": {
            "decision": scan.decision,
            "risk": scan.risk,
            "summary": scrub_dev_text(scan.summary, 500) if scan.summary else None,
            "matched_rules": scan.matched_rules or [],
            "block_reason": (scrub_dev_text(scan.block_reason, 500) if scan.block_reason else None),
            "review_title": scan.review_title,
            "review_description": scan.review_description,
            "review_severity": scan.review_severity,
            "log": scrub_dev_value(scan.log),
            "error": scan.error,
            "timing": {
                "plugin_e2e_ms": timing.plugin_e2e_ms,
                "engine_ms": timing.engine_ms,
                "request_ms": timing.request_ms,
                "transport_ms": timing.transport_ms,
            },
        },
        "card": card,
        "hook": {
            **_hook_outcome(mapped),
            "unattended_block": scan.decision == "review"
            and (mapped or {}).get("action") == "block",
        },
    }


def build_scan_error_dev_event(
    *,
    plan: PlanIR,
    pending_args: dict[str, Any] | None,
    failure: ScanFailure,
    mapped: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pending = last_pending_step(plan)
    pending_tool = pending.tool if pending else "unknown"
    local_raw = _pending_command_from_args(pending_args)
    card = None
    if mapped and mapped.get("action") == "approve":
        card = {"message": mapped.get("message")}
    return {
        "event": "scan_error",
        "session_id": plan.metadata.session_id,
        "run_id": plan.run_id,
        "tool_call_id": plan.metadata.tool_call_id,
        "tool": pending_tool,
        "local": {
            "args": scrub_dev_value(pending_args or {}),
            "command": scrub_dev_text(local_raw) if local_raw else None,
            "command_chars": len(local_raw) if local_raw else 0,
        },
        "failure": {
            "kind": failure.kind,
            "status": failure.status,
            "retry_after_sec": failure.retry_after_sec,
            "detail": scrub_dev_text(failure.detail, 400),
        },
        "hook": _hook_outcome(mapped),
        "card": card,
    }
