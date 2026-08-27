"""Hosted Sentrook HTTP client — scan, feedback, latency."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Literal

from .auth import ScanAuthConfig, build_scan_auth_headers
from .planir import PlanIR, last_pending_step, planir_to_dict
from .sanitize import maybe_sanitize_planir
from .scan_error_policy import ScanFailure, parse_retry_after_seconds

logger = logging.getLogger("sentrook")

FeedbackMode = Literal["off", "submit"]
ApprovalResolution = Literal["allow-once", "allow-always", "deny", "timeout", "cancelled"]


@dataclass
class ScanResponse:
    block: bool = False
    decision: Literal["allow", "review", "block"] = "allow"
    risk: float | None = None
    summary: str | None = None
    pending_tool: str | None = None
    matched_rules: list[str] | None = None
    block_reason: str | None = None
    review_title: str | None = None
    review_description: str | None = None
    review_severity: str | None = None
    log: dict[str, Any] | None = None
    timing: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class ScanTiming:
    plugin_e2e_ms: int
    engine_ms: int | None
    request_ms: int | None
    transport_ms: int | None
    sanitize_enabled: bool
    sanitize_ms: int


@dataclass
class PostScanResult:
    scan: ScanResponse
    timing: ScanTiming


def _read_positive_int(value: Any) -> int | None:
    if isinstance(value, (int, float)) and value >= 0:
        return int(round(value))
    return None


def extract_engine_ms(scan: ScanResponse) -> int | None:
    if scan.timing and (ms := _read_positive_int(scan.timing.get("engine_ms"))) is not None:
        return ms
    if scan.log and (ms := _read_positive_int(scan.log.get("total_ms"))) is not None:
        return ms
    return None


def extract_request_ms(scan: ScanResponse) -> int | None:
    if scan.timing:
        return _read_positive_int(scan.timing.get("request_ms"))
    return None


def compute_transport_ms(plugin_e2e_ms: int, engine_ms: int | None) -> int | None:
    if engine_ms is None:
        return None
    return max(0, plugin_e2e_ms - engine_ms)


def build_scan_timing(
    scan: ScanResponse,
    plugin_e2e_ms: int,
    *,
    sanitize_enabled: bool = True,
    sanitize_ms: int = 0,
) -> ScanTiming:
    engine_ms = extract_engine_ms(scan)
    request_ms = extract_request_ms(scan)
    return ScanTiming(
        plugin_e2e_ms=plugin_e2e_ms,
        engine_ms=engine_ms,
        request_ms=request_ms,
        transport_ms=compute_transport_ms(plugin_e2e_ms, engine_ms),
        sanitize_enabled=sanitize_enabled,
        sanitize_ms=sanitize_ms,
    )


def _http_request(
    url: str,
    *,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout_sec: float,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in headers.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp_headers, resp.read()
    except urllib.error.HTTPError as exc:
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        payload = exc.read() if exc.fp else b""
        return exc.code, resp_headers, payload
    except urllib.error.URLError as exc:
        raise OSError(str(exc.reason)) from exc


def _parse_scan_response(payload: bytes) -> ScanResponse:
    doc = json.loads(payload.decode("utf-8"))
    decision = doc.get("decision", "allow")
    if decision not in ("allow", "review", "block"):
        decision = "allow"
    return ScanResponse(
        block=bool(doc.get("block")),
        decision=decision,
        risk=doc.get("risk"),
        summary=doc.get("summary"),
        pending_tool=doc.get("pending_tool"),
        matched_rules=doc.get("matched_rules"),
        block_reason=doc.get("block_reason"),
        review_title=doc.get("review_title"),
        review_description=doc.get("review_description"),
        review_severity=doc.get("review_severity"),
        log=doc.get("log") if isinstance(doc.get("log"), dict) else None,
        timing=doc.get("timing") if isinstance(doc.get("timing"), dict) else None,
        error=doc.get("error"),
    )


def post_scan(
    url: str,
    timeout_ms: int,
    plan: PlanIR,
    auth: ScanAuthConfig | None = None,
) -> PostScanResult | ScanFailure:
    auth = auth or ScanAuthConfig(api_key=None, oidc=None)
    plan_dict = planir_to_dict(plan)
    sanitized = maybe_sanitize_planir(plan_dict)
    outbound = sanitized.plan
    sanitize_ms = sanitized.sanitize_ms

    timeout_sec = max(0.001, timeout_ms / 1000.0)
    started = time.perf_counter()
    deadline = started + timeout_sec
    retried_429 = False
    body = json.dumps(outbound).encode("utf-8")

    # Mint OIDC outside the scan deadline. Cold discovery+token can take ~2s on
    # remote identity hosts; folding that into timeout_ms caused intermittent
    # "unreachable or timed out" with a correct URL and credentials.
    try:
        headers = build_scan_auth_headers(auth, timeout=30.0)
    except Exception as exc:
        detail = str(exc)
        logger.warning("scan auth failed: %s", detail[:200])
        status_hint = 401 if "401" in detail or "unauthorized" in detail.lower() else None
        return ScanFailure(
            ok=False,
            kind="http" if status_hint else "network",
            status=status_hint,
            detail=detail[:200] or "scan auth failed",
        )

    while True:
        try:
            status, resp_headers, payload = _http_request(
                f"{url.rstrip('/')}/scan",
                method="POST",
                headers=headers,
                body=body,
                timeout_sec=max(0.001, deadline - time.perf_counter()),
            )
        except OSError as exc:
            msg = str(exc)
            if "timed out" in msg.lower():
                return ScanFailure(ok=False, kind="timeout", detail=msg)
            return ScanFailure(ok=False, kind="network", detail=msg)

        if status == 200:
            scan = _parse_scan_response(payload)
            plugin_e2e_ms = int(round((time.perf_counter() - started) * 1000))
            timing = build_scan_timing(
                scan,
                plugin_e2e_ms,
                sanitize_enabled=True,
                sanitize_ms=sanitize_ms,
            )
            return PostScanResult(scan=scan, timing=timing)

        detail = payload.decode("utf-8", errors="replace")[:200]

        if status == 429 and not retried_429:
            retry_after_sec = parse_retry_after_seconds(resp_headers.get("retry-after")) or 1.0
            wait_sec = retry_after_sec
            remaining = deadline - time.perf_counter()
            if wait_sec + 0.05 < remaining:
                retried_429 = True
                logger.warning(
                    "scan HTTP 429: rate limited; Retry-After=%s; retrying",
                    retry_after_sec,
                )
                time.sleep(min(wait_sec, max(0, remaining - 0.05)))
                continue

        if status == 429:
            retry_after_sec = parse_retry_after_seconds(resp_headers.get("retry-after"))
            logger.warning("scan HTTP 429: rate limited")
            return ScanFailure(
                ok=False,
                kind="rate_limited",
                status=429,
                retry_after_sec=retry_after_sec,
                detail=detail or "rate limited",
            )

        logger.warning("scan HTTP %s: %s", status, detail)
        return ScanFailure(
            ok=False,
            kind="http",
            status=status,
            detail=detail or f"HTTP {status}",
        )


def post_feedback(
    url: str,
    auth: ScanAuthConfig,
    *,
    plan: PlanIR | dict[str, Any],
    resolution: ApprovalResolution,
    log: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> None:
    plan_dict = planir_to_dict(plan) if isinstance(plan, PlanIR) else plan
    outbound = maybe_sanitize_planir(plan_dict).plan
    body = json.dumps(
        {
            "plan": outbound,
            "resolution": resolution,
            "log": log,
            "provenance": provenance or {},
        }
    ).encode("utf-8")
    try:
        headers = build_scan_auth_headers(auth)
        status, _resp_headers, payload = _http_request(
            f"{url.rstrip('/')}/feedback",
            method="POST",
            headers=headers,
            body=body,
            timeout_sec=10.0,
        )
        text = payload.decode("utf-8", errors="replace")
        if status != 200:
            logger.warning("feedback HTTP %s: %s", status, text[:200] or "(empty)")
            return
        try:
            doc = json.loads(text) if text else {}
        except json.JSONDecodeError:
            doc = {}
        fb_status = doc.get("status") or doc.get("feedback_status") or "ok"
        reason = doc.get("reason") or doc.get("feedback_reason")
        if fb_status in ("skipped", "error", "feedback_error"):
            logger.warning("feedback not submitted: status=%s reason=%s", fb_status, reason)
            return
        logger.info("feedback %s", fb_status)
    except OSError as exc:
        logger.warning("feedback post failed: %s", exc)


def post_latency(
    url: str,
    auth: ScanAuthConfig,
    plan: PlanIR,
    scan: ScanResponse,
    timing: ScanTiming,
) -> None:
    pending_tool = last_pending_step(plan)
    tool_name = pending_tool.tool if pending_tool else "unknown"
    body = json.dumps(
        {
            "tool_call_id": plan.metadata.tool_call_id,
            "session_id": plan.metadata.session_id,
            "run_id": plan.run_id,
            "pending_tool": tool_name,
            "decision": scan.decision,
            "plugin_e2e_ms": timing.plugin_e2e_ms,
            "engine_ms": timing.engine_ms,
            "request_ms": timing.request_ms,
            "transport_ms": timing.transport_ms,
            "sanitize_enabled": timing.sanitize_enabled,
            "sanitize_ms": timing.sanitize_ms,
        }
    ).encode("utf-8")
    try:
        headers = build_scan_auth_headers(auth)
        _http_request(
            f"{url.rstrip('/')}/latency",
            method="POST",
            headers=headers,
            body=body,
            timeout_sec=5.0,
        )
    except OSError:
        pass


def get_health(url: str, auth: ScanAuthConfig | None = None, timeout_sec: float = 5.0) -> tuple[bool, str]:
    auth = auth or ScanAuthConfig(api_key=None, oidc=None)
    try:
        headers = build_scan_auth_headers(auth, timeout=timeout_sec)
        status, _headers, payload = _http_request(
            f"{url.rstrip('/')}/health",
            method="GET",
            headers=headers,
            body=None,
            timeout_sec=timeout_sec,
        )
        if status == 200:
            return True, payload.decode("utf-8", errors="replace")[:200]
        return False, f"HTTP {status}"
    except Exception as exc:
        return False, str(exc)
