"""PlanIR 1.0 sanitization — parity with OpenClaw ``sanitize.ts``."""

from __future__ import annotations

import copy
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any

CREDENTIAL_VAR_SEGMENT = re.compile(
    r"(?:^|_)(pass(?:wd|word)?|secret|token|api[_-]?key|auth|credential|bearer)(?:_|$)",
    re.IGNORECASE,
)
ENV_ASSIGNMENT = re.compile(
    r"((?:export\s+)?)((?=[A-Za-z_])[A-Za-z0-9_]+)\s*=\s*"
    r"(?:\"[^\"\\]*(?:\\.[^\"\\]*)*\"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s;|&]+)",
    re.IGNORECASE,
)
CLI_SECRET_FLAG = re.compile(
    r"(--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)"
    r"(?:-\w+)?)(\s*=\s*|\s+)(?:\"[^\"\\]*(?:\\.[^\"\\]*)*\"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s;|&]+)",
    re.IGNORECASE,
)

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SENSITIVE_PATH_RE = re.compile(
    r"auth-profiles(?:\.json)?|openclaw-agent\.sqlite|database\.sqlite|"
    r"~?/\.ssh(?:/[^\s\"']*)?|MEMORY\.md|authorized_keys|/etc/[^\s\"']+",
    re.IGNORECASE,
)
COMMANDISH_LINE_RE = re.compile(
    r"^.*(?:\bcurl\b|\bwget\b|\btar\b.+\||\bPOST\b|\bpip\s+install\b).*$",
    re.IGNORECASE | re.MULTILINE,
)
INJECTION_MARKERS = re.compile(
    r"ignore (?:all |the |your )?(?:previous|prior|above|earlier)\b|"
    r"ignore (?:all |the |your )?safety\b|"
    r"(?:system|admin|developer)\s+override|"
    r"disregard (?:all |the |your )?(?:previous|prior|above|earlier|safety)|"
    r"system prompt|exfiltrat|"
    r"upload \S*(?:auth-profiles|openclaw-agent\.sqlite|database\.sqlite|"
    r"credentials|secrets|\.ssh)\S*\s+to\s+https?://|"
    r"(?:important|mandatory|required)\s*:\s*before\b.{0,60}\b(?:upload|send|post|transmit)\b",
    re.IGNORECASE,
)

SIGNAL_SEP = " … "
MARKER_PAD = 60
CONTENT_LIKE_KEYS = frozenset({"content", "text", "body", "message", "command", "cmd"})


@dataclass
class SanitizeRules:
    version: int = 1
    redacted: str = "[REDACTED]"
    truncated: str = "[TRUNCATED]"
    result_text_max_chars: int = 500
    intent_max_chars: int = 1000
    string_leaf_max_chars: int = 500
    session_hash_prefix: str = "sess_"
    session_hash_hex_chars: int = 12
    credential_field: re.Pattern[str] = field(
        default_factory=lambda: re.compile(
            r"(token|password|passwd|(?<![a-z])pass(?![a-z])|secret|api[_-]?key|auth|credential|bearer)",
            re.IGNORECASE,
        )
    )
    secret_value_patterns: tuple[re.Pattern[str], ...] = (
        re.compile(
            r"(?<![-_])\b(api[_-]?key|password|secret)\b(?!\s*=)|bearer\s+[A-Za-z0-9._=-]+",
            re.IGNORECASE,
        ),
        re.compile(
            r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{8,}|"
            r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-[a-z0-9]{10,}"
        ),
        re.compile(r"sk-ant-[a-z0-9-]{10,}"),
        re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
        re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
        re.compile(
            r"xox[baprs]-[A-Za-z0-9-]{10,}|xoxe(?:\.xox[bp])?-\d-[A-Za-z0-9]+|xapp-\d-[A-Za-z0-9-]+",
            re.IGNORECASE,
        ),
        re.compile(r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_-]+"),
        re.compile(r"[MNO][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,110}"),
        re.compile(
            r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/(?:\d+|\[REDACTED\])/[A-Za-z0-9_-]+"
        ),
        re.compile(r"\b\d{5,16}:A[A-Za-z0-9_-]{34}\b"),
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        re.compile(r"\bEAA[A-Za-z0-9]{40,}\b"),
        re.compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
        re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"),
        re.compile(r"hf_[A-Za-z0-9]{20,}"),
        re.compile(r"gsk_[A-Za-z0-9]{20,}"),
        re.compile(
            r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----"
        ),
    )
    pii_patterns: tuple[re.Pattern[str], ...] = (
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        re.compile(
            r"\b\d{1,5}[A-Za-z]?\s+(?:[A-Z][a-z]+|[A-Z]{1,3}\d?[A-Za-z]?)\s+"
            r"(?:[A-Z][a-z]+\s+){0,3}(?:Street|St\.?|Road|Rd\.?|Avenue|Ave\.?|"
            r"Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?|"
            r"Terrace|Ter\.?|Close|Crescent|Cres\.?|Grove|Hill|Row)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\b(?:GIR\s?0AA|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2})\b", re.IGNORECASE),
        re.compile(
            r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
            re.IGNORECASE,
        ),
        re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b"),
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        re.compile(r"\+?[0-9][0-9()\-\s.]{7,}[0-9]"),
    )
    pii_arg_keys: frozenset[str] = frozenset(
        {"command", "cmd", "message", "text", "content", "body"}
    )
    allowed_result_keys: frozenset[str] = frozenset(
        {"ok", "content_type", "byte_size", "excerpt", "extracted", "flags"}
    )


DEFAULT_RULES = SanitizeRules()


@dataclass(frozen=True)
class SanitizePlanIRResult:
    plan: dict[str, Any]
    sanitize_ms: int


@dataclass(frozen=True)
class SanitizationConfig:
    enabled: bool = True


ALWAYS_SANITIZE = SanitizationConfig(enabled=True)


def resolve_sanitization_config(
    _plugin_cfg: dict[str, Any] | None = None,
    _env: dict[str, str] | None = None,
) -> SanitizationConfig:
    return ALWAYS_SANITIZE


def hash_session_id(session_id: str, rules: SanitizeRules = DEFAULT_RULES) -> str:
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return f"{rules.session_hash_prefix}{digest[: rules.session_hash_hex_chars]}"


def _is_content_like_key(key: str | None) -> bool:
    return bool(key and key.lower() in CONTENT_LIKE_KEYS)


def _signal_budgets(limit: int) -> tuple[int, int]:
    if limit <= 40:
        head = max(8, limit // 3)
        tail = max(6, limit // 4)
    elif limit <= 100:
        head = max(24, limit // 3)
        tail = max(16, limit // 4)
    else:
        head = min(120, max(40, limit // 4))
        tail = min(80, max(24, limit // 6))
    reserved = len(SIGNAL_SEP) * 2 + 3
    while head + tail + reserved > limit and (head > 8 or tail > 6):
        if head >= tail and head > 8:
            head -= 1
        elif tail > 6:
            tail -= 1
        else:
            break
    return head, tail


def _collect_signal_spans(text: str) -> list[tuple[int, int, str]]:
    raw: list[tuple[int, int, str]] = []

    for pattern in (URL_RE, SENSITIVE_PATH_RE):
        for match in pattern.finditer(text):
            raw.append((match.start(), match.end(), match.group(0)))

    for match in COMMANDISH_LINE_RE.finditer(text):
        snippet = match.group(0).strip()
        if not snippet or URL_RE.search(snippet):
            continue
        raw.append((match.start(), match.end(), snippet))

    for match in INJECTION_MARKERS.finditer(text):
        start = max(0, match.start() - MARKER_PAD)
        end = min(len(text), match.end() + MARKER_PAD)
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end_raw = text.find("\n", match.end())
        line_end = len(text) if line_end_raw < 0 else line_end_raw
        if line_start >= start - 20:
            start = min(start, line_start)
        if line_end <= end + 20:
            end = max(end, line_end)
        snippet = text[start:end].strip()
        if snippet:
            raw.append((start, end, snippet))

    raw.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    merged: list[tuple[int, int, str]] = []
    for span in raw:
        if merged and span[0] < merged[-1][1]:
            continue
        merged.append(span)
    return merged


def _aligned_tail(text: str, budget: int) -> str:
    if budget <= 0 or not text:
        return ""
    tail = text[-budget:]
    for sep in ("\n", " ", "\t"):
        idx = tail.find(sep)
        if idx >= 0 and idx <= min(24, max(0, budget // 4)):
            return tail[idx + 1 :]
    return tail


def pack_signal_excerpt(text: str, limit: int, ellipsis: str = "...") -> str:
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit <= 3:
        return ellipsis[:limit]

    head_budget, tail_budget = _signal_budgets(limit)
    head = text[:head_budget]
    tail = _aligned_tail(text, tail_budget)

    signals: list[str] = []
    seen: set[str] = set()
    for _start, _end, snippet in _collect_signal_spans(text):
        snippet = snippet.strip()
        if not snippet or snippet in seen or snippet in head:
            continue
        seen.add(snippet)
        signals.append(snippet)

    parts = [head]
    used = len(head)

    for signal in signals:
        max_signal = max(24, limit // 2)
        if len(signal) > max_signal:
            url_match = URL_RE.search(signal)
            if url_match and len(url_match.group(0)) <= max_signal:
                signal = url_match.group(0)
            elif url_match and len(url_match.group(0)) > max_signal:
                signal = f"{url_match.group(0)[: max_signal - 3]}{ellipsis}"
            else:
                signal = f"{signal[: max_signal - 3]}{ellipsis}"
        cost = len(SIGNAL_SEP) + len(signal)
        if used + cost > limit:
            break
        remaining_after = limit - (used + cost)
        need_tail = bool(tail and tail not in head)
        min_tail_room = len(SIGNAL_SEP) + min(len(tail), 8) if need_tail else 0
        if remaining_after < min_tail_room and need_tail:
            break
        parts.append(signal)
        used += cost

    if tail and tail not in head:
        already = any(tail in p for p in parts[1:])
        room = limit - used - len(SIGNAL_SEP)
        if not already and room >= 8:
            clipped = tail if len(tail) <= room else f"{tail[-(room - 3) :]}{ellipsis}"
            parts.append(clipped)
        elif not already and room > 3:
            parts.append(ellipsis[:room])

    packed = SIGNAL_SEP.join(parts)
    if len(packed) > limit:
        packed = f"{packed[: limit - 3]}{ellipsis}"
    if packed == head and len(head) < limit:
        return f"{head[: limit - 3]}{ellipsis}" if limit > 3 else ellipsis[:limit]
    return packed


def _truncate(
    text: str,
    limit: int,
    rules: SanitizeRules,
    *,
    signal_aware: bool = False,
) -> str:
    if len(text) <= limit:
        return text
    if limit <= 3:
        return rules.truncated
    if signal_aware:
        return pack_signal_excerpt(text, limit, "...")
    return f"{text[: limit - 3]}..."


def _is_credential_var_name(name: str) -> bool:
    return bool(CREDENTIAL_VAR_SEGMENT.search(name))


def _is_shell_style_assignment_name(name: str) -> bool:
    if "_" in name or name == name.upper() or name == name.lower():
        return True
    return False


def _redact_env_secret_assignments(text: str, placeholder: str) -> str:
    def repl(match: re.Match[str]) -> str:
        export_prefix = match.group(1)
        name = match.group(2)
        if not _is_credential_var_name(name):
            return match.group(0)
        if not export_prefix and not _is_shell_style_assignment_name(name):
            return match.group(0)
        return f"{export_prefix}{name}={placeholder}"

    return ENV_ASSIGNMENT.sub(repl, text)


def _redact_cli_secret_flags(text: str, placeholder: str) -> str:
    def repl(match: re.Match[str]) -> str:
        return f"{match.group(1)}{match.group(2)}{placeholder}"

    return CLI_SECRET_FLAG.sub(repl, text)


def _apply_patterns(text: str, patterns: tuple[re.Pattern[str], ...], replacement: str) -> str:
    out = text
    for pattern in patterns:
        out = pattern.sub(replacement, out)
    return out


def _apply_secret_patterns(text: str, rules: SanitizeRules) -> str:
    cleaned = _redact_env_secret_assignments(text, rules.redacted)
    cleaned = _redact_cli_secret_flags(cleaned, rules.redacted)
    return _apply_patterns(cleaned, rules.secret_value_patterns, rules.redacted)


def scrub_secrets(text: str, rules: SanitizeRules = DEFAULT_RULES) -> str:
    return _apply_secret_patterns(text, rules)


def _scrub_string(
    text: str,
    rules: SanitizeRules,
    *,
    pii: bool,
    max_chars: int,
    key: str | None = None,
) -> str:
    cleaned = _apply_secret_patterns(text, rules)
    if pii:
        cleaned = _apply_patterns(cleaned, rules.pii_patterns, rules.redacted)
    return _truncate(
        cleaned,
        max_chars,
        rules,
        signal_aware=_is_content_like_key(key),
    )


def _is_credential_field(key: str, rules: SanitizeRules) -> bool:
    return bool(rules.credential_field.search(key))


def _sanitize_value(
    value: Any,
    rules: SanitizeRules,
    *,
    parent_key: str | None,
    pii: bool,
    max_chars: int,
    pii_keys: frozenset[str] | None = None,
) -> Any:
    pii_keys = pii_keys or frozenset()
    if parent_key is not None and _is_credential_field(parent_key, rules):
        return rules.redacted
    if isinstance(value, str):
        return _scrub_string(value, rules, pii=pii, max_chars=max_chars, key=parent_key)
    if isinstance(value, list):
        return [
            _sanitize_value(
                item,
                rules,
                parent_key=None,
                pii=False,
                max_chars=max_chars,
                pii_keys=pii_keys,
            )
            for item in value
        ]
    if isinstance(value, dict):
        nested_pii = pii or (parent_key is not None and parent_key.lower() == "env")
        return _sanitize_mapping(value, rules, pii=nested_pii, max_chars=max_chars, pii_keys=pii_keys)
    return value


def _sanitize_mapping(
    mapping: dict[str, Any],
    rules: SanitizeRules,
    *,
    pii: bool,
    max_chars: int,
    pii_keys: frozenset[str] | None = None,
) -> dict[str, Any]:
    pii_keys = pii_keys or frozenset()
    out: dict[str, Any] = {}
    for key, value in mapping.items():
        out[key] = _sanitize_value(
            value,
            rules,
            parent_key=key,
            pii=pii or key in pii_keys,
            max_chars=max_chars,
            pii_keys=pii_keys,
        )
    return out


def _sanitize_result_summary(summary: dict[str, Any], rules: SanitizeRules) -> dict[str, Any]:
    out = dict(summary)
    excerpt = summary.get("excerpt")
    if isinstance(excerpt, str):
        scrubbed = _scrub_string(
            excerpt,
            rules,
            pii=False,
            max_chars=rules.result_text_max_chars,
            key="excerpt",
        )
        out["excerpt"] = scrubbed
        out["byte_size"] = len(scrubbed.encode("utf-8"))
    extracted = summary.get("extracted")
    if isinstance(extracted, dict):
        cleaned = dict(extracted)
        commands = extracted.get("commands")
        if isinstance(commands, list):
            cleaned["commands"] = [
                _scrub_string(
                    str(item),
                    rules,
                    pii=True,
                    max_chars=rules.string_leaf_max_chars,
                    key="command",
                )
                if isinstance(item, str)
                else item
                for item in commands
            ]
        out["extracted"] = cleaned
    return out


def _sanitize_step(step: dict[str, Any], rules: SanitizeRules) -> dict[str, Any]:
    out = dict(step)
    args = step.get("args")
    if isinstance(args, dict):
        out["args"] = _sanitize_mapping(
            args,
            rules,
            pii=False,
            max_chars=rules.string_leaf_max_chars,
            pii_keys=rules.pii_arg_keys,
        )
    result_summary = step.get("result_summary")
    if isinstance(result_summary, dict):
        out["result_summary"] = _sanitize_result_summary(result_summary, rules)
    return out


def _rewrite_run_id(run_id: str, original_session_id: str, hashed_session_id: str) -> str:
    prefix = f"{original_session_id}:"
    if run_id.startswith(prefix):
        return f"{hashed_session_id}:{run_id[len(prefix) :]}"
    return run_id


def sanitize_planir_dict(
    payload: dict[str, Any],
    rules: SanitizeRules = DEFAULT_RULES,
) -> dict[str, Any]:
    data = copy.deepcopy(payload)
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        data["metadata"] = metadata

    original_session_id = metadata.get("session_id")
    if isinstance(original_session_id, str) and original_session_id:
        hashed = hash_session_id(original_session_id, rules)
        metadata["session_id"] = hashed
        run_id = data.get("run_id")
        if isinstance(run_id, str):
            data["run_id"] = _rewrite_run_id(run_id, original_session_id, hashed)

    intent = data.get("intent")
    if isinstance(intent, str):
        data["intent"] = _scrub_string(
            intent,
            rules,
            pii=True,
            max_chars=rules.intent_max_chars,
        )

    steps = data.get("steps")
    if isinstance(steps, list):
        data["steps"] = [
            _sanitize_step(item, rules)
            for item in steps
            if isinstance(item, dict)
        ]

    return data


def sanitize_planir(
    plan: dict[str, Any],
    rules: SanitizeRules = DEFAULT_RULES,
) -> SanitizePlanIRResult:
    started = time.perf_counter()
    cleaned = sanitize_planir_dict(plan, rules)
    elapsed_ms = int(round((time.perf_counter() - started) * 1000))
    return SanitizePlanIRResult(plan=cleaned, sanitize_ms=elapsed_ms)


def maybe_sanitize_planir(
    plan: dict[str, Any],
    _config: SanitizationConfig = ALWAYS_SANITIZE,
    rules: SanitizeRules = DEFAULT_RULES,
) -> SanitizePlanIRResult:
    return sanitize_planir(plan, rules)
