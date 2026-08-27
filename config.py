"""Plugin settings resolution."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from .auth import (
    ScanAuthConfig,
    env_with_hermes_dotenv,
    has_scan_credentials,
    parse_scan_base_url,
    resolve_scan_auth_config,
    url_requires_scan_auth,
)
from .scan_client import FeedbackMode
from .scan_endpoint import resolve_scan_base_url
from .scan_error_policy import OnScanError, resolve_on_scan_error

DEFAULT_SCAN_TIMEOUT_MS = 60_000


@dataclass(frozen=True)
class PluginConfig:
    url: str
    auth: ScanAuthConfig
    timeout_ms: int
    feedback_mode: FeedbackMode
    on_scan_error: OnScanError


def resolve_scan_timeout_ms(cfg_timeout: Any, env: dict[str, str] | None = None) -> int:
    env = env or dict(os.environ)
    if isinstance(cfg_timeout, (int, float)) and cfg_timeout > 0:
        return int(round(cfg_timeout))
    env_ms = env.get("SENTROOK_SCAN_TIMEOUT_MS", "").strip()
    if env_ms:
        try:
            parsed = float(env_ms)
            if parsed > 0:
                return int(round(parsed))
        except ValueError:
            pass
    return DEFAULT_SCAN_TIMEOUT_MS


def resolve_feedback_mode(settings: dict[str, Any], env: dict[str, str] | None = None) -> FeedbackMode:
    env = env or dict(os.environ)
    feedback_cfg = settings.get("feedback")
    if isinstance(feedback_cfg, dict):
        mode_raw = feedback_cfg.get("mode")
    else:
        mode_raw = settings.get("feedback_mode")
    mode_raw = (
        mode_raw
        if isinstance(mode_raw, str) and mode_raw.strip()
        else env.get("SENTROOK_FEEDBACK_MODE", "submit")
    )
    return "submit" if mode_raw in ("submit", "queue") else "off"


def resolve_plugin_config(settings: dict[str, Any] | None = None) -> PluginConfig:
    settings = settings or {}
    env = env_with_hermes_dotenv()
    # Pass merged dotenv — do not rely on os.environ alone (gateway may not export
    # SENTROOK_* into the process env even when they live in ~/.hermes/.env).
    raw_url = resolve_scan_base_url(settings, env)
    ok, href, _https = parse_scan_base_url(raw_url)
    if not ok:
        raise ValueError(f"scan base URL is invalid ({href}): {raw_url}")
    url = href
    timeout_ms = resolve_scan_timeout_ms(settings.get("timeout_ms"), env)
    auth = resolve_scan_auth_config(settings, env)
    feedback_mode = resolve_feedback_mode(settings, env)
    on_scan_error = resolve_on_scan_error(
        plugin_config=settings.get("on_scan_error"),
        env=env,
    )
    return PluginConfig(
        url=url,
        auth=auth,
        timeout_ms=timeout_ms,
        feedback_mode=feedback_mode,
        on_scan_error=on_scan_error,
    )


def config_summary(config: PluginConfig) -> str:
    if has_scan_credentials(config.auth):
        auth_label = "oidc" if config.auth.oidc else "apikey"
    elif url_requires_scan_auth(config.url):
        auth_label = "missing"
    else:
        auth_label = "off"
    return (
        f"url={config.url}, scan-auth={auth_label}, timeout={config.timeout_ms}ms, "
        f"onScanError={config.on_scan_error}, feedback={config.feedback_mode}, sanitization=on"
    )
