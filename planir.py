"""PlanIR 1.0 builder — behavioral twin of OpenClaw ``planir.ts``."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal

from .sanitize import pack_signal_excerpt

IntentKind = Literal["user", "cron", "subagent", "system"]
Json = dict[str, Any]

EXEC_COMMAND_ALIASES = ("cmd", "shell", "script", "line", "code", "data")
WRITE_PATH_ALIASES = ("file", "filepath", "target")
# Body keys that fold into PlanIR ``message.text`` (channel-agnostic).
MESSAGE_BODY_ALIASES = ("body", "content", "message", "msg", "comment")

# Hermes host tool → PlanIR vocabulary (OpenClaw / hosted rules).
# Missed entries fail open at L1 (“No matching rules”) — keep this table
# complete for any high-risk Hermes tool we intend to cover.
# Conditional aliases (e.g. process write/submit) live in canonical_tool_name.
#
# Messaging: every tool whose job is *delivering an outbound body* maps to
# PlanIR ``message``. Platform/channel belongs in ``target`` / ``channel`` args
# — YAIRA rules must not key on transport. Unified Hermes ``send_message``
# already covers Discord, Telegram, Slack, Matrix, Signal, … Host-specific
# send twins (DM / comment reply) alias here too. Do **not** alias fetch/list/
# admin tools (e.g. Hermes ``discord`` fetch_messages) — those are not sinks.
TOOL_NAME_ALIASES: dict[str, str] = {
    "terminal": "exec",
    "execute_code": "exec",  # Python sandbox; emit as exec so command/code rules apply
    "write_file": "write",
    "patch": "edit",
    "send_message": "message",
    "read_file": "read",
    "web_extract": "web_fetch",
    "yb_send_dm": "message",
    "feishu_drive_reply_comment": "message",
    "feishu_drive_add_comment": "message",
}

# process(action=write|submit) injects stdin into a background terminal without a
# new terminal/exec call — fold onto exec so command regexes still fire.
PROCESS_EXEC_ACTIONS = frozenset({"write", "submit"})

# Tools whose args are treated as shell/code for review-card “run:” prefix.
EXEC_TOOLS = frozenset({"exec", "terminal", "execute_code", "process"})


URL_RE = __import__("re").compile(r"https?://[^\s\"'<>]+")
PATH_RE = __import__("re").compile(r"(?:/[\w.\-]+)+")
INJECTION_MARKERS = __import__("re").compile(
    r"(?:ignore (?:all |the |your )?(?:previous|prior|above|earlier)\b|"
    r"ignore (?:all |the |your )?safety\b|"
    r"(?:system|admin|developer)\s+override|"
    r"disregard (?:all |the |your )?(?:previous|prior|above|earlier|safety)|"
    r"system prompt|</s>|<\|im_start\|>|exfiltrat|"
    r"upload \S*(?:auth-profiles|openclaw-agent\.sqlite|database\.sqlite|"
    r"credentials|secrets|\.ssh)\S*\s+to\s+https?://|"
    r"(?:important|mandatory|required)\s*:\s*before\b.{0,60}\b(?:upload|send|post|transmit)\b)",
    __import__("re").IGNORECASE,
)

EXCERPT_LIMIT = 500
EXTRACTED_LIMIT = 20
REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"
STRING_LEAF_MAX = 500
CREDENTIAL_FIELD = __import__("re").compile(
    r"(token|password|passwd|(?<![a-z])pass(?![a-z])|secret|api[_-]?key|auth|credential|bearer)",
    __import__("re").IGNORECASE,
)
CONTENT_LIKE_KEYS = frozenset({"content", "text", "body", "message", "command", "cmd", "code"})


@dataclass
class ResultSummaryExtracted:
    urls: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)


@dataclass
class ResultSummaryFlags:
    truncated: bool = False
    injection_markers: bool = False


@dataclass
class ResultSummary:
    ok: bool
    byte_size: int
    excerpt: str
    extracted: ResultSummaryExtracted
    flags: ResultSummaryFlags
    content_type: str | None = None


@dataclass
class PlanStep:
    id: str
    tool: str
    status: Literal["executed", "pending"]
    args: Json
    result_summary: ResultSummary | None = None


@dataclass
class PlanMetadata:
    adapter: str
    hook: str
    agent_id: str | None = None
    session_id: str | None = None
    tool_call_id: str | None = None
    step_seq: int | None = None
    batch_size: int | None = None


@dataclass
class PlanIR:
    version: Literal["1.0"]
    run_id: str
    steps: list[PlanStep]
    metadata: PlanMetadata
    intent: str | None = None
    intent_kind: IntentKind | None = None


@dataclass
class SnapshotCall:
    tool: str
    args: Json
    result_text: str | None = None
    result_ok: bool | None = True
    content_type: str | None = None
    command: str | None = None
    result_summary: ResultSummary | None = None


def stringify_arg_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(stringify_arg_value(item) for item in value)
    if isinstance(value, dict):
        return " ".join(stringify_arg_value(v) for v in value.values())
    return str(value)


def _write_body_text(args: Json) -> str:
    pieces: list[str] = []
    if "content" in args:
        pieces.append(stringify_arg_value(args["content"]))
    if "edits" in args:
        pieces.append(stringify_arg_value(args["edits"]))
    # Hermes ``patch`` (replace + V4A) and OpenClaw edit shapes.
    for key in ("newText", "new_string", "old_string", "text", "body", "patch"):
        if key in args:
            pieces.append(stringify_arg_value(args[key]))
    return " ".join(p for p in pieces if p)


def canonical_tool_name(tool: str, args: Json | None = None) -> str:
    """Map Hermes host tool names onto PlanIR tools the hosted rules know.

    Coverage-critical: PlanIR ``steps[].tool`` / pending_tool must use the
    shared corpus vocabulary (OpenClaw names today), not raw host ids. Hermes
    ``terminal`` is the ``exec`` equivalent. Emitting ``terminal`` caused a
    silent L1 early-exit allow (“No matching rules”) for obvious exfil curls —
    verify/health still green, shell coverage effectively off. Every new host
    tool alias needs an explicit entry in ``TOOL_NAME_ALIASES`` + a regression
    test.

    ``process`` is conditional: only ``action`` in {write, submit} (stdin inject)
    maps to ``exec``; list/poll/log/wait/kill/close stay as ``process``.
    """
    if tool == "process":
        action = str((args or {}).get("action") or "").strip().lower()
        if action in PROCESS_EXEC_ACTIONS:
            return "exec"
        return "process"
    return TOOL_NAME_ALIASES.get(tool, tool)


def canonicalize_tool_args(tool: str, args: Json) -> Json:
    if not args:
        return {}
    canonical_tool = canonical_tool_name(tool, args)
    if canonical_tool == "exec":
        out = dict(args)
        if "command" not in out:
            for alias in EXEC_COMMAND_ALIASES:
                if alias in out:
                    out["command"] = out.pop(alias)
                    break
        if "command" in out:
            out["command"] = stringify_arg_value(out["command"])
        return out
    if canonical_tool in ("write", "edit"):
        out = dict(args)
        if "path" not in out:
            for alias in WRITE_PATH_ALIASES:
                if alias in out:
                    out["path"] = out.pop(alias)
                    break
        if "path" in out:
            out["path"] = stringify_arg_value(out["path"])
        body = _write_body_text(out)
        if body:
            out["content"] = body
        return out
    if canonical_tool == "message":
        out = dict(args)
        if "text" not in out:
            for alias in MESSAGE_BODY_ALIASES:
                if alias in out:
                    out["text"] = out.pop(alias)
                    break
        if "text" in out:
            out["text"] = stringify_arg_value(out["text"])
        return out
    return dict(args)


def redact_args(args: Json) -> Json:
    out: Json = {}
    for key, value in args.items():
        if CREDENTIAL_FIELD.search(key):
            out[key] = REDACTED
        elif isinstance(value, str) and len(value) > STRING_LEAF_MAX:
            out[key] = (
                pack_signal_excerpt(value, STRING_LEAF_MAX)
                if key.lower() in CONTENT_LIKE_KEYS
                else TRUNCATED
            )
        elif isinstance(value, dict):
            out[key] = redact_args(value)
        elif isinstance(value, list):
            out[key] = [
                redact_args(item)
                if isinstance(item, dict)
                else (
                    TRUNCATED
                    if isinstance(item, str) and len(item) > STRING_LEAF_MAX
                    else item
                )
                for item in value
            ]
        else:
            out[key] = value
    return out


def build_result_summary(
    text: str,
    *,
    ok: bool = True,
    content_type: str | None = None,
    command: str | None = None,
) -> ResultSummary:
    body = text or ""
    byte_size = len(body.encode("utf-8"))
    excerpt = body[:EXCERPT_LIMIT]
    truncated = len(body) > EXCERPT_LIMIT
    urls = list(dict.fromkeys(URL_RE.findall(body)))[:EXTRACTED_LIMIT]
    paths = list(dict.fromkeys(PATH_RE.findall(body)))[:EXTRACTED_LIMIT]
    commands = [str(command)] if command else []
    return ResultSummary(
        ok=ok,
        content_type=content_type,
        byte_size=byte_size,
        excerpt=excerpt,
        extracted=ResultSummaryExtracted(urls=urls, paths=paths, commands=commands),
        flags=ResultSummaryFlags(truncated=truncated, injection_markers=bool(INJECTION_MARKERS.search(body))),
    )


def _result_summary_to_dict(summary: ResultSummary | None) -> dict[str, Any] | None:
    if summary is None:
        return None
    return {
        "ok": summary.ok,
        "content_type": summary.content_type,
        "byte_size": summary.byte_size,
        "excerpt": summary.excerpt,
        "extracted": {
            "urls": summary.extracted.urls,
            "paths": summary.extracted.paths,
            "commands": summary.extracted.commands,
        },
        "flags": {
            "truncated": summary.flags.truncated,
            "injection_markers": summary.flags.injection_markers,
        },
    }


def make_plan_step(
    step_id: str,
    tool: str,
    args: Json,
    status: Literal["executed", "pending"],
    result_summary: ResultSummary | None = None,
) -> PlanStep:
    return PlanStep(
        id=step_id,
        tool=canonical_tool_name(tool, args),
        status=status,
        args=redact_args(canonicalize_tool_args(tool, args)),
        result_summary=result_summary,
    )


def last_pending_step(plan: PlanIR) -> PlanStep | None:
    for step in reversed(plan.steps):
        if step.status == "pending":
            return step
    return None


def _coerce_snapshot_call(value: SnapshotCall | dict[str, Any]) -> SnapshotCall:
    if isinstance(value, SnapshotCall):
        return value
    return SnapshotCall(
        tool=str(value.get("tool", "")),
        args=value.get("args") or {},
        result_text=value.get("result_text") or value.get("resultText"),
        result_ok=value.get("result_ok", value.get("resultOk", True)),
        content_type=value.get("content_type") or value.get("contentType"),
        command=value.get("command"),
        result_summary=value.get("result_summary") or value.get("resultSummary"),
    )


def build_planir_snapshot(
    *,
    executed: list[SnapshotCall | dict[str, Any]],
    pending: SnapshotCall | dict[str, Any],
    co_pending: list[SnapshotCall | dict[str, Any]] | None = None,
    run_id: str,
    intent: str | None = None,
    intent_kind: IntentKind | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
    adapter: str = "hermes",
    hook: str = "pre_tool_call",
    tool_call_id: str | None = None,
    step_seq: int | None = None,
    batch_size: int | None = None,
) -> PlanIR:
    co_pending = [_coerce_snapshot_call(call) for call in (co_pending or [])]
    pending_call = _coerce_snapshot_call(pending)
    executed_calls = [_coerce_snapshot_call(call) for call in executed]
    steps: list[PlanStep] = []
    index = 1
    for call in executed_calls:
        summary = call.result_summary
        if summary is None and call.result_text is not None:
            summary = build_result_summary(
                call.result_text,
                ok=call.result_ok if call.result_ok is not None else True,
                content_type=call.content_type,
                command=call.command,
            )
        steps.append(make_plan_step(f"s{index}", call.tool, call.args, "executed", summary))
        index += 1
    for call in co_pending:
        steps.append(make_plan_step(f"s{index}", call.tool, call.args, "pending"))
        index += 1
    steps.append(make_plan_step(f"s{index}", pending_call.tool, pending_call.args, "pending"))

    return PlanIR(
        version="1.0",
        run_id=run_id,
        intent=intent,
        intent_kind=intent_kind,
        steps=steps,
        metadata=PlanMetadata(
            adapter=adapter,
            agent_id=agent_id or "main",
            session_id=session_id,
            hook=hook,
            tool_call_id=tool_call_id,
            step_seq=step_seq,
            batch_size=batch_size,
        ),
    )


def planir_to_dict(plan: PlanIR) -> dict[str, Any]:
    """Serialize PlanIR to JSON-compatible dict."""

    def step_dict(step: PlanStep) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": step.id,
            "tool": step.tool,
            "status": step.status,
            "args": step.args,
        }
        rs = _result_summary_to_dict(step.result_summary)
        if rs is not None:
            out["result_summary"] = rs
        return out

    meta = plan.metadata
    return {
        "version": plan.version,
        "run_id": plan.run_id,
        "intent": plan.intent,
        "intent_kind": plan.intent_kind,
        "steps": [step_dict(s) for s in plan.steps],
        "metadata": {
            "adapter": meta.adapter,
            "agent_id": meta.agent_id,
            "session_id": meta.session_id,
            "hook": meta.hook,
            "tool_call_id": meta.tool_call_id,
            "step_seq": meta.step_seq,
            "batch_size": meta.batch_size,
        },
    }


def _sort_keys_deep(value: Any) -> Any:
    if isinstance(value, list):
        return [_sort_keys_deep(item) for item in value]
    if isinstance(value, dict):
        return {key: _sort_keys_deep(value[key]) for key in sorted(value)}
    return value


def canonical_planir_json(plan: PlanIR) -> str:
    """Stable JSON for golden parity (sorted keys, no undefined)."""
    return json.dumps(_sort_keys_deep(planir_to_dict(plan)), separators=(",", ":"))
