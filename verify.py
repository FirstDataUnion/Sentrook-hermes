"""``hermes sentrook verify`` — honest coverage checks (no Hermes doctor required)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .auth import (
    clear_scan_token_cache,
    env_with_hermes_dotenv,
    get_scan_access_token,
    has_scan_credentials,
    resolve_hermes_state_dir,
    resolve_scan_auth_config,
    url_requires_scan_auth,
)
from .config import resolve_plugin_config
from .scan_client import get_health

PLUGIN_ID = "sentrook"
EXPECTED_HOOKS = frozenset(
    {
        "pre_llm_call",
        "pre_tool_call",
        "post_tool_call",
        "post_approval_response",
        "on_session_finalize",
        "on_session_reset",
        "subagent_start",
    }
)


@dataclass
class VerifyCheck:
    name: str
    ok: bool
    detail: str


@dataclass
class VerifyResult:
    ok: bool
    url: str
    checks: list[VerifyCheck] = field(default_factory=list)
    covering: bool = False


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _parse_provides_hooks(manifest: Path) -> set[str]:
    """Read provides_hooks from plugin.yaml (YAML if available, else line scan)."""
    data = _load_yaml(manifest)
    hooks = data.get("provides_hooks")
    if isinstance(hooks, list):
        return {str(h).strip() for h in hooks if str(h).strip()}

    declared: set[str] = set()
    in_hooks = False
    for line in manifest.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("provides_hooks:"):
            in_hooks = True
            continue
        if not in_hooks:
            continue
        if stripped and not line[:1].isspace() and not stripped.startswith("#"):
            break
        m = re.match(r"^-\s+([A-Za-z0-9_]+)\s*$", stripped)
        if m:
            declared.add(m.group(1))
    return declared


def _plugin_install_dir(state_dir: Path) -> Path:
    return state_dir / "plugins" / PLUGIN_ID


def check_plugin_installed(state_dir: Path) -> VerifyCheck:
    root = _plugin_install_dir(state_dir)
    manifest = root / "plugin.yaml"
    if not manifest.is_file():
        return VerifyCheck(
            name="plugin install",
            ok=False,
            detail=(
                f"missing {manifest} — install with "
                f"`hermes plugins install …/integrations/hermes/plugin --enable` "
                f"or symlink into ~/.hermes/plugins/{PLUGIN_ID}"
            ),
        )
    return VerifyCheck(
        name="plugin install",
        ok=True,
        detail=f"found {manifest}",
    )


def check_expected_hooks(state_dir: Path) -> VerifyCheck:
    manifest = _plugin_install_dir(state_dir) / "plugin.yaml"
    if not manifest.is_file():
        return VerifyCheck(
            name="hooks manifest",
            ok=False,
            detail="plugin.yaml missing — cannot check provides_hooks",
        )
    declared = _parse_provides_hooks(manifest)
    missing = sorted(EXPECTED_HOOKS - declared)
    if missing:
        return VerifyCheck(
            name="hooks manifest",
            ok=False,
            detail=f"plugin.yaml missing hooks: {', '.join(missing)}",
        )
    return VerifyCheck(
        name="hooks manifest",
        ok=True,
        detail=f"provides_hooks includes {len(EXPECTED_HOOKS)} required hooks",
    )


def _list_under_key(text: str, key: str) -> list[str]:
    """Best-effort YAML list items under ``key:`` (no PyYAML required)."""
    items: list[str] = []
    in_key = False
    key_re = re.compile(rf"^(\s*){re.escape(key)}:\s*(.*)$")
    for line in text.splitlines():
        m = key_re.match(line)
        if m:
            in_key = True
            rest = m.group(2).strip()
            if rest.startswith("[") and rest.endswith("]"):
                inner = rest[1:-1].strip()
                if inner:
                    items.extend(p.strip().strip("'\"") for p in inner.split(",") if p.strip())
                return items
            continue
        if not in_key:
            continue
        if line.strip() and not line[:1].isspace() and not line.strip().startswith("#"):
            break
        # Nested key at same-or-less indent ends the list; require list-item dash.
        lm = re.match(r"^\s+-\s+(.+?)\s*$", line)
        if lm:
            items.append(lm.group(1).strip().strip("'\""))
        elif re.match(r"^\s+[A-Za-z0-9_]+:\s*", line):
            break
    return items


def check_plugin_enabled(state_dir: Path) -> VerifyCheck:
    cfg_path = state_dir / "config.yaml"
    if not cfg_path.is_file():
        return VerifyCheck(
            name="plugin enabled",
            ok=False,
            detail=f"missing {cfg_path} — run hermes setup / enable the plugin",
        )
    cfg = _load_yaml(cfg_path)
    text = cfg_path.read_text(encoding="utf-8")

    if cfg:
        plugins = cfg.get("plugins") if isinstance(cfg.get("plugins"), dict) else {}
        enabled = plugins.get("enabled") if isinstance(plugins, dict) else None
        disabled = plugins.get("disabled") if isinstance(plugins, dict) else None
        entries = plugins.get("entries") if isinstance(plugins, dict) else None

        if isinstance(disabled, list) and PLUGIN_ID in disabled:
            return VerifyCheck(
                name="plugin enabled",
                ok=False,
                detail=f"{PLUGIN_ID} is in plugins.disabled — run: hermes plugins enable {PLUGIN_ID}",
            )
        if isinstance(enabled, list) and PLUGIN_ID in enabled:
            return VerifyCheck(
                name="plugin enabled",
                ok=True,
                detail=f"{PLUGIN_ID} listed in plugins.enabled",
            )
        if isinstance(entries, dict) and PLUGIN_ID in entries:
            entry = entries.get(PLUGIN_ID)
            if isinstance(entry, dict) and entry.get("enabled") is False:
                return VerifyCheck(
                    name="plugin enabled",
                    ok=False,
                    detail=f"plugins.entries.{PLUGIN_ID}.enabled is false",
                )
            return VerifyCheck(
                name="plugin enabled",
                ok=True,
                detail=f"plugins.entries.{PLUGIN_ID} present (not explicitly disabled)",
            )
    else:
        # Text fallback when PyYAML is unavailable in the Hermes runtime.
        if PLUGIN_ID in _list_under_key(text, "disabled"):
            return VerifyCheck(
                name="plugin enabled",
                ok=False,
                detail=f"{PLUGIN_ID} is in plugins.disabled — run: hermes plugins enable {PLUGIN_ID}",
            )
        if PLUGIN_ID in _list_under_key(text, "enabled"):
            return VerifyCheck(
                name="plugin enabled",
                ok=True,
                detail=f"{PLUGIN_ID} listed in plugins.enabled (text scan)",
            )
        if re.search(
            rf"(?m)^\s*{re.escape(PLUGIN_ID)}:\s*$",
            text,
        ) and "entries:" in text:
            if re.search(
                rf"(?ms){re.escape(PLUGIN_ID)}:\s*(?:.*\n)*?\s+enabled:\s*false\b",
                text,
            ):
                return VerifyCheck(
                    name="plugin enabled",
                    ok=False,
                    detail=f"plugins.entries.{PLUGIN_ID}.enabled is false",
                )
            return VerifyCheck(
                name="plugin enabled",
                ok=True,
                detail=f"plugins.entries.{PLUGIN_ID} present (text scan)",
            )

    return VerifyCheck(
        name="plugin enabled",
        ok=False,
        detail=(
            f"{PLUGIN_ID} not in plugins.enabled — run: hermes plugins enable {PLUGIN_ID} "
            f"(then restart the gateway)"
        ),
    )


def format_verify_report(result: VerifyResult) -> str:
    lines = [f"=== Sentrook verify ({result.url}) ==="]
    for check in result.checks:
        mark = "✓" if check.ok else "✗"
        lines.append(f"{mark} {check.name}: {check.detail}")
    if result.ok:
        lines.append(
            "OK — ready to cover if the gateway was restarted since install/configure. "
            "Exercise a tool call and confirm `sentrook:` lines in ~/.hermes/logs/agent.log."
        )
    else:
        lines.append("FAILED — fix the items above, then re-run: hermes sentrook verify")
        lines.append("not covering: one or more required checks failed.")
    return "\n".join(lines)


def run_verify(
    *,
    settings: dict[str, Any] | None = None,
    env: dict[str, str] | None = None,
    state_dir: Path | None = None,
    skip_health: bool = False,
    skip_mint: bool = False,
) -> VerifyResult:
    settings = settings or {}
    env = env_with_hermes_dotenv(env)
    state = state_dir or resolve_hermes_state_dir(env)

    try:
        # resolve_plugin_config merges ~/.hermes/.env via env_with_hermes_dotenv()
        # internally; point HERMES_HOME / state via env before calling if needed.
        config = resolve_plugin_config(settings)
    except ValueError as exc:
        return VerifyResult(
            ok=False,
            url="?",
            covering=False,
            checks=[VerifyCheck(name="config", ok=False, detail=str(exc))],
        )

    auth = resolve_scan_auth_config(settings, env)
    checks: list[VerifyCheck] = [
        check_plugin_installed(state),
        check_expected_hooks(state),
        check_plugin_enabled(state),
    ]

    needs_auth = url_requires_scan_auth(config.url)
    if needs_auth:
        creds_ok = has_scan_credentials(auth)
        checks.append(
            VerifyCheck(
                name="scan credentials",
                ok=creds_ok,
                detail=(
                    ("oidc client_credentials" if auth.oidc else "api_key")
                    if creds_ok
                    else "missing SENTROOK_SCAN_CLIENT_ID+SECRET in ~/.hermes/.env"
                ),
            )
        )
    else:
        checks.append(
            VerifyCheck(
                name="scan credentials",
                ok=True,
                detail="HTTP scan URL — scan auth not required",
            )
        )

    if not skip_health:
        ok, detail = get_health(config.url, auth)
        checks.append(
            VerifyCheck(
                name="scan service health",
                ok=ok,
                detail=detail[:200] if detail else ("ok" if ok else "failed"),
            )
        )
    else:
        checks.append(VerifyCheck(name="scan service health", ok=True, detail="skipped"))

    if (
        not skip_mint
        and needs_auth
        and auth.oidc is not None
        and has_scan_credentials(auth)
    ):
        clear_scan_token_cache()
        try:
            get_scan_access_token(auth.oidc)
            checks.append(
                VerifyCheck(
                    name="OIDC token mint",
                    ok=True,
                    detail=f"client_credentials OK at {auth.oidc.issuer}",
                )
            )
        except Exception as exc:
            checks.append(
                VerifyCheck(
                    name="OIDC token mint",
                    ok=False,
                    detail=f"{exc} — presence in .env is not enough",
                )
            )

    all_ok = all(c.ok for c in checks)
    installed = next(c for c in checks if c.name == "plugin install").ok
    enabled = next(c for c in checks if c.name == "plugin enabled").ok
    creds = next(c for c in checks if c.name == "scan credentials").ok
    covering = all_ok and installed and enabled and creds
    return VerifyResult(ok=all_ok, url=config.url, checks=checks, covering=covering)
