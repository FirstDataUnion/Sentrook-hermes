"""Sentrook Hermes plugin — hosted scan loop."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from . import cli
from .approval_map import map_approval_choice
from .auth import (
    env_with_hermes_dotenv,
    has_scan_credentials,
    resolve_scan_auth_config,
    url_requires_scan_auth,
)
from .config import PluginConfig, config_summary, resolve_plugin_config
from .intent import (
    RunIntent,
    extract_prompt_text,
    is_unattended,
    resolve_intent_kind,
    resolve_session_platform,
)
from .planir import SnapshotCall, build_planir_snapshot, last_pending_step, planir_to_dict
from .review_copy import build_review_message, pending_display_command
from .rule_key import build_rule_key, build_scan_error_rule_key
from .scan_client import (
    PostScanResult,
    post_feedback,
    post_latency,
    post_scan,
)
from .scan_error_policy import is_scan_failure, scan_error_to_directive

logger = logging.getLogger("sentrook")

MAX_TRAJECTORY = 200
MAX_RESULT_TEXT = 20_000

_plugin_config: PluginConfig | None = None
_sessions: dict[str, SessionState] = {}
_pending_by_rule_key: dict[str, dict[str, Any]] = {}


@dataclass
class SessionState:
    run_intents: dict[str, RunIntent] = field(default_factory=dict)
    executed: list[SnapshotCall] = field(default_factory=list)
    pending: dict[str, dict[str, Any]] = field(default_factory=dict)
    step_seq: int = 0
    subagent: bool = False


def _session_id(**kwargs: Any) -> str:
    return str(
        kwargs.get("session_id") or kwargs.get("task_id") or kwargs.get("session_key") or "default"
    )


def _resolve_run_id(event_run_id: Any, ctx_run_id: Any) -> str:
    return str(event_run_id or ctx_run_id or "run_1")


def _get_session(key: str) -> SessionState:
    if key not in _sessions:
        _sessions[key] = SessionState()
    return _sessions[key]


def _get_settings_from_ctx(ctx: Any) -> dict[str, Any]:
    for name in ("get_settings", "settings", "plugin_settings", "get_config"):
        attr = getattr(ctx, name, None)
        if callable(attr):
            try:
                val = attr()
                if isinstance(val, dict):
                    return val
            except TypeError:
                try:
                    val = attr("sentrook")
                    if isinstance(val, dict):
                        return val
                except Exception:
                    pass
            except Exception:
                pass
        elif isinstance(attr, dict):
            return attr
    return {}


def _resolve_live_config(settings: dict[str, Any] | None = None) -> PluginConfig:
    """Prefer settings passed in, else config captured at ``register()``, else env defaults."""
    if settings:
        return resolve_plugin_config(settings)
    if _plugin_config is not None:
        return _plugin_config
    return resolve_plugin_config({})


def _result_to_text(result: Any, error: str | None = None) -> str:
    text = ""
    if error:
        text = str(error)
    elif isinstance(result, str):
        text = result
    elif result is not None:
        try:
            text = json.dumps(result)
        except (TypeError, ValueError):
            text = str(result)
    if len(text) > MAX_RESULT_TEXT:
        return text[:MAX_RESULT_TEXT]
    return text


def _directive_to_dict(directive: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"action": directive.action, "message": directive.message}
    if directive.rule_key:
        out["rule_key"] = directive.rule_key
    return out


def _remember_pending(
    st: SessionState,
    tool_call_id: Any,
    tool_name: str,
    args: dict[str, Any],
) -> None:
    if tool_call_id:
        st.pending[str(tool_call_id)] = {"tool": tool_name, "args": args or {}}


def _drop_session_pending(session_id: Any, tool_call_id: Any) -> None:
    if not session_id or not tool_call_id:
        return
    st = _sessions.get(str(session_id))
    if st is not None:
        st.pending.pop(str(tool_call_id), None)


def _stash_review_pending(
    rule_key: str,
    *,
    plan,
    log: dict[str, Any] | None,
    pending_args: dict[str, Any],
    session_id: str,
    tool_call_id: Any,
    scan_error: bool = False,
) -> None:
    _pending_by_rule_key[rule_key] = {
        "plan": planir_to_dict(plan),
        "log": log,
        "pending_args": pending_args,
        "session_id": session_id,
        "tool_call_id": str(tool_call_id) if tool_call_id else None,
        "scan_error": scan_error,
    }


PLUGIN_ERROR_BLOCK = "Sentrook plugin error; this tool was not scanned or run."


def _translate_scan_response(
    scan_result: PostScanResult,
    *,
    plan,
    pending_args: dict[str, Any],
    unattended: bool,
    platform: str | None = None,
    session_id: str | None = None,
    tool_call_id: Any = None,
) -> dict[str, Any] | None:
    scan = scan_result.scan
    if scan.block or scan.decision == "block":
        message = (
            scan.block_reason
            or scan.summary
            or "Sentrook blocked this tool call due to security policy"
        )
        return {"action": "block", "message": message}

    if scan.decision == "review":
        if unattended:
            logger.info(
                "unattended review (%s, platform=%s): blocking instead of escalating",
                plan.intent_kind or "unknown",
                platform or "none",
            )
            return {
                "action": "block",
                "message": scan.summary
                or "Sentrook flagged this tool call for review (unattended)",
            }

        pending = last_pending_step(plan)
        pending_tool = pending.tool if pending else "tool"
        rule_key = build_rule_key(plan, pending_args=pending_args)
        message = build_review_message(
            pending_tool=pending_tool,
            pending_args=pending_args,
            scan_summary=scan.summary,
            scan_description=scan.review_description,
        )
        _stash_review_pending(
            rule_key,
            plan=plan,
            log=scan.log if isinstance(scan.log, dict) else None,
            pending_args=pending_args,
            session_id=session_id or "",
            tool_call_id=tool_call_id,
        )
        return {"action": "approve", "message": message, "rule_key": rule_key}

    return None


def _format_scan_timing_log(plan, scan_result: PostScanResult) -> str:
    pending = last_pending_step(plan)
    timing = scan_result.timing
    scan = scan_result.scan
    return json.dumps(
        {
            "event": "scan_timing",
            "tool_call_id": plan.metadata.tool_call_id,
            "session_id": plan.metadata.session_id,
            "run_id": plan.run_id,
            "pending_tool": pending.tool if pending else "unknown",
            "decision": scan.decision,
            "plugin_e2e_ms": timing.plugin_e2e_ms,
            "engine_ms": timing.engine_ms,
            "request_ms": timing.request_ms,
            "transport_ms": timing.transport_ms,
            "sanitize_enabled": timing.sanitize_enabled,
            "sanitize_ms": timing.sanitize_ms,
        }
    )


def on_pre_llm_call(**kwargs: Any) -> None:
    """Store intent markers; never inject prompt text."""
    sid = _session_id(**kwargs)
    st = _get_session(sid)
    run_id = _resolve_run_id(kwargs.get("run_id"), kwargs.get("agent_run_id"))
    prompt = extract_prompt_text(**kwargs)
    if prompt:
        from .intent import classify_intent

        st.run_intents[run_id] = RunIntent(intent=prompt, kind=classify_intent(prompt))


def on_pre_tool_call(tool_name: str, args: dict, **kwargs: Any) -> dict | None:
    """Build PlanIR → sanitize → POST /scan → map decision."""
    try:
        config = _resolve_live_config()

        sid = _session_id(**kwargs)
        st = _get_session(sid)
        env = env_with_hermes_dotenv()
        # Hermes gateway keeps platform in a ContextVar; kwargs/os.environ alone miss Discord.
        platform = resolve_session_platform(
            kwargs.get("platform") if isinstance(kwargs.get("platform"), str) else None,
            env=env,
        )
        unattended = is_unattended(env=env, platform=platform, subagent=st.subagent)

        pending_call = SnapshotCall(tool=tool_name, args=args or {})
        co_pending: list[SnapshotCall] = []
        tool_call_id = kwargs.get("tool_call_id")
        for call_id, peer in st.pending.items():
            if tool_call_id and call_id == tool_call_id:
                continue
            co_pending.append(SnapshotCall(tool=peer["tool"], args=peer["args"]))

        st.step_seq += 1
        run_id = _resolve_run_id(kwargs.get("run_id"), kwargs.get("agent_run_id"))
        run_intent = st.run_intents.get(run_id)
        intent_kind = resolve_intent_kind(
            run_intent.kind if run_intent else None,
            run_intent.intent if run_intent else None,
            env=env,
            platform=str(platform) if platform else None,
            subagent=st.subagent,
        )

        plan = build_planir_snapshot(
            executed=st.executed[-MAX_TRAJECTORY:],
            pending=pending_call,
            co_pending=co_pending or None,
            run_id=f"{sid}:{run_id}",
            intent=run_intent.intent if run_intent else None,
            intent_kind=intent_kind,
            session_id=sid,
            agent_id=kwargs.get("agent_id"),
            tool_call_id=str(tool_call_id) if tool_call_id else None,
            step_seq=st.step_seq,
            batch_size=len(co_pending) + 1 if co_pending else None,
        )

        # Re-resolve auth each call so ~/.hermes/.env edits apply without restart.
        live_auth = resolve_scan_auth_config({}, env)
        scan_result = post_scan(config.url, config.timeout_ms, plan, live_auth)
        if is_scan_failure(scan_result):
            logger.warning(
                "scan failure kind=%s status=%s detail=%s url=%s",
                scan_result.kind,
                getattr(scan_result, "status", None),
                (scan_result.detail or "")[:160],
                config.url,
            )
            rule_key = build_scan_error_rule_key(
                scan_result.kind,
                tool=tool_name,
                pending_args=args or {},
            )
            directive = scan_error_to_directive(
                scan_result,
                on_scan_error=config.on_scan_error,
                unattended=unattended,
                rule_key=rule_key,
            )
            if directive is None:
                logger.warning(
                    "scan error (%s); continuing without scan (onScanError=allow)",
                    scan_result.kind,
                )
                _remember_pending(st, tool_call_id, tool_name, args or {})
                return None
            mapped = _directive_to_dict(directive)
            if directive.action == "approve":
                _remember_pending(st, tool_call_id, tool_name, args or {})
                _stash_review_pending(
                    rule_key,
                    plan=plan,
                    log=None,
                    pending_args=args or {},
                    session_id=sid,
                    tool_call_id=tool_call_id,
                    scan_error=True,
                )
            return mapped

        logger.info(_format_scan_timing_log(plan, scan_result))
        post_latency(config.url, live_auth, plan, scan_result.scan, scan_result.timing)
        mapped = _translate_scan_response(
            scan_result,
            plan=plan,
            pending_args=args or {},
            unattended=unattended,
            platform=platform,
            session_id=sid,
            tool_call_id=tool_call_id,
        )
        if mapped is None or mapped.get("action") == "approve":
            _remember_pending(st, tool_call_id, tool_name, args or {})
        return mapped
    except Exception as exc:
        logger.warning("pre_tool_call failed: %s", exc)
        detail = str(exc).replace("\n", " ").strip()[:160]
        message = PLUGIN_ERROR_BLOCK
        if detail:
            message = f"{PLUGIN_ERROR_BLOCK} Detail: {detail}"
        return {"action": "block", "message": message}


def on_post_tool_call(tool_name: str, args: dict, result: str = "", **kwargs: Any) -> None:
    """Append executed tool to session trajectory."""
    try:
        sid = _session_id(**kwargs)
        st = _get_session(sid)
        tool_call_id = kwargs.get("tool_call_id")
        call = st.pending.pop(str(tool_call_id), None) if tool_call_id else None
        if not call:
            call = {"tool": tool_name, "args": args or {}}

        tool = call["tool"]
        call_args = call.get("args") or {}
        command = pending_display_command(call_args)

        st.executed.append(
            SnapshotCall(
                tool=tool,
                args=call_args,
                result_text=_result_to_text(result, kwargs.get("error")),
                result_ok=not kwargs.get("error"),
                command=command,
            )
        )
        if len(st.executed) > MAX_TRAJECTORY:
            del st.executed[: len(st.executed) - MAX_TRAJECTORY]
    except Exception as exc:
        logger.warning("post_tool_call failed: %s", exc)


def on_post_approval_response(**kwargs: Any) -> None:
    """Join via pattern_key / rule_key; best-effort /feedback."""
    pattern_key = str(kwargs.get("pattern_key") or "")
    rule_key = pattern_key.removeprefix("plugin_rule:") if pattern_key else ""
    pending = _pending_by_rule_key.pop(rule_key, None) if rule_key else None
    choice = str(kwargs.get("choice") or kwargs.get("decision") or "")
    resolution = map_approval_choice(choice)
    logger.info(
        "post_approval_response choice=%s resolution=%s rule_key=%s pending=%s",
        choice or None,
        resolution,
        rule_key or None,
        bool(pending),
    )
    if pending and resolution in ("deny", "timeout", "cancelled"):
        _drop_session_pending(pending.get("session_id"), pending.get("tool_call_id"))
    if not pending or not resolution:
        return
    try:
        config = _resolve_live_config()
        if config.feedback_mode == "off" and resolution != "allow-always":
            return
        if resolution in ("allow-once", "allow-always", "deny"):
            plan_doc = pending.get("plan")
            if isinstance(plan_doc, dict):
                env = env_with_hermes_dotenv()
                live_auth = resolve_scan_auth_config({}, env)
                hermes_choice = choice.strip().lower() or None
                post_feedback(
                    config.url,
                    live_auth,
                    plan=plan_doc,
                    resolution=resolution,
                    log=pending.get("log") if isinstance(pending.get("log"), dict) else None,
                    provenance={
                        "adapter": "hermes",
                        "rule_key": rule_key,
                        "hermes_choice": hermes_choice,
                    },
                )
    except Exception as exc:
        logger.warning("post_approval_response feedback failed: %s", exc)


def on_session_finalize(**kwargs: Any) -> None:
    sid = _session_id(**kwargs)
    _sessions.pop(sid, None)
    stale = [key for key, value in _pending_by_rule_key.items() if value.get("session_id") == sid]
    for key in stale:
        _pending_by_rule_key.pop(key, None)


def on_session_reset(**kwargs: Any) -> None:
    on_session_finalize(**kwargs)


def on_subagent_start(**kwargs: Any) -> None:
    """Mark the *child* session as subagent (Hermes passes child_session_id)."""
    child = kwargs.get("child_session_id") or kwargs.get("session_id")
    parent = kwargs.get("parent_session_id")
    marked: list[str] = []
    if child:
        sid = str(child)
        _get_session(sid).subagent = True
        marked.append(sid)
    # Fall back so older hook shapes still set something.
    if not marked:
        sid = _session_id(**kwargs)
        _get_session(sid).subagent = True
        marked.append(sid)
    logger.info(
        "subagent_start child=%s parent=%s marked=%s",
        child,
        parent,
        marked,
    )


def register(ctx: Any) -> None:
    global _plugin_config
    settings = _get_settings_from_ctx(ctx)
    try:
        _plugin_config = resolve_plugin_config(settings)
    except ValueError as exc:
        logger.error("sentrook plugin config invalid: %s — using defaults", exc)
        _plugin_config = resolve_plugin_config({})

    ctx.register_hook("pre_llm_call", on_pre_llm_call)
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("post_approval_response", on_post_approval_response)
    ctx.register_hook("on_session_finalize", on_session_finalize)
    ctx.register_hook("on_session_reset", on_session_reset)
    ctx.register_hook("subagent_start", on_subagent_start)
    cli.register_cli(ctx)

    if url_requires_scan_auth(_plugin_config.url) and not has_scan_credentials(_plugin_config.auth):
        logger.warning(
            "hosted scan URL has no credentials — run: hermes sentrook configure "
            "(or set SENTROOK_SCAN_CLIENT_ID + SENTROOK_SCAN_CLIENT_SECRET in ~/.hermes/.env)"
        )

    logger.info(
        "sentrook plugin registered (%s, min_hermes=0.18.2)",
        config_summary(_plugin_config),
    )
