"""Scan auth for hosted Sentrook — OIDC client_credentials or static API key."""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .scan_endpoint import DEFAULT_OIDC_ISSUER

# Re-export: default follows the pinned scan deploy (prod vs *dev*).
DEFAULT_SCAN_ISSUER = DEFAULT_OIDC_ISSUER
DEFAULT_SCAN_AUDIENCE = "sentrook"
DEFAULT_SCAN_SCOPE = "sentrook.scan"
TOKEN_EXPIRY_SKEW_SEC = 60

CLIENT_ID_VAR = "SENTROOK_SCAN_CLIENT_ID"
CLIENT_SECRET_VAR = "SENTROOK_SCAN_CLIENT_SECRET"
API_KEY_VAR = "SENTROOK_SCAN_API_KEY"


@dataclass(frozen=True)
class ScanOidcCredentials:
    client_id: str
    client_secret: str
    issuer: str
    audience: str
    scope: str


@dataclass(frozen=True)
class ScanAuthConfig:
    api_key: str | None
    oidc: ScanOidcCredentials | None


@dataclass
class _TokenCache:
    access_token: str
    expires_at_ms: float
    cache_key: str


_token_cache: _TokenCache | None = None


def clear_scan_token_cache() -> None:
    global _token_cache
    _token_cache = None


def parse_dotenv_text(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        if "=" not in trimmed:
            continue
        key, _, value = trimmed.partition("=")
        key = key.strip()
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        if key:
            out[key] = value
    return out


def read_dotenv_file(dotenv_file: str | Path) -> dict[str, str]:
    path = Path(dotenv_file)
    if not path.is_file():
        return {}
    try:
        return parse_dotenv_text(path.read_text(encoding="utf-8"))
    except OSError:
        return {}


def resolve_hermes_state_dir(env: dict[str, str] | None = None) -> Path:
    env = env or dict(os.environ)
    if env.get("HERMES_STATE_DIR", "").strip():
        return Path(env["HERMES_STATE_DIR"].strip())
    home = env.get("HERMES_HOME", "").strip() or env.get("HOME", "").strip() or "/home/node"
    return Path(home) / ".hermes"


def env_with_hermes_dotenv(
    env: dict[str, str] | None = None,
    *,
    state_dir: str | Path | None = None,
    dotenv_path: str | Path | None = None,
) -> dict[str, str]:
    env = dict(env or os.environ)
    dotenv_file = (
        Path(dotenv_path)
        if dotenv_path
        else (Path(state_dir) if state_dir else resolve_hermes_state_dir(env)) / ".env"
    )
    from_file = read_dotenv_file(dotenv_file)
    merged = dict(env)
    for key, value in from_file.items():
        if not merged.get(key, "").strip():
            merged[key] = value
    return merged


def resolve_secret_string(
    raw: Any,
    env: dict[str, str],
    env_fallback: str | None = None,
) -> str | None:
    if isinstance(raw, str):
        trimmed = raw.strip()
        return trimmed or None
    if isinstance(raw, dict):
        if raw.get("source") == "env" and isinstance(raw.get("id"), str) and raw["id"]:
            value = env.get(raw["id"], "")
            if isinstance(value, str) and value.strip():
                return value.strip()
    if env_fallback:
        fallback = env.get(env_fallback, "")
        if isinstance(fallback, str) and fallback.strip():
            return fallback.strip()
    return None


def resolve_api_key(raw: Any, env: dict[str, str] | None = None) -> str | None:
    return resolve_secret_string(raw, env or dict(os.environ), API_KEY_VAR)


def strip_trailing_slashes(value: str) -> str:
    end = len(value)
    while end > 0 and value[end - 1] == "/":
        end -= 1
    return value[:end]


def resolve_scan_auth_config(
    cfg: dict[str, Any],
    env: dict[str, str] | None = None,
) -> ScanAuthConfig:
    env = env or dict(os.environ)
    api_key = resolve_api_key(cfg.get("api_key") or cfg.get("apiKey"), env)
    client_id = resolve_secret_string(
        cfg.get("client_id") or cfg.get("clientId"), env, CLIENT_ID_VAR
    )
    client_secret = resolve_secret_string(
        cfg.get("client_secret") or cfg.get("clientSecret"), env, CLIENT_SECRET_VAR
    )
    issuer = (
        resolve_secret_string(cfg.get("oidc_issuer") or cfg.get("oidcIssuer"), env, "SENTROOK_OIDC_ISSUER")
        or DEFAULT_SCAN_ISSUER
    )
    audience = (
        resolve_secret_string(
            cfg.get("oidc_audience") or cfg.get("oidcAudience"), env, "SENTROOK_OIDC_AUDIENCE"
        )
        or DEFAULT_SCAN_AUDIENCE
    )
    scope = (
        resolve_secret_string(cfg.get("oidc_scope") or cfg.get("oidcScope"), env, "SENTROOK_OIDC_SCOPE")
        or DEFAULT_SCAN_SCOPE
    )
    oidc = (
        ScanOidcCredentials(
            client_id=client_id,
            client_secret=client_secret,
            issuer=strip_trailing_slashes(issuer),
            audience=audience,
            scope=scope,
        )
        if client_id and client_secret
        else None
    )
    return ScanAuthConfig(api_key=api_key, oidc=oidc)


def parse_scan_base_url(raw: str) -> tuple[bool, str, str]:
    """Return (ok, href_or_reason, https_flag_or_empty)."""
    try:
        parsed = urllib.parse.urlparse(raw.strip())
    except ValueError:
        return False, "invalid scan URL", ""
    if parsed.scheme not in ("http", "https"):
        return False, f"scan URL must be http or https (got {parsed.scheme})", ""
    if parsed.username or parsed.password:
        return False, "scan URL must not include credentials", ""
    host = parsed.hostname or ""
    if not host or not __import__("re").fullmatch(r"[A-Za-z0-9._:-]+", host):
        return False, "scan URL hostname is invalid", ""
    if host in ("169.254.169.254", "::ffff:169.254.169.254"):
        return False, "scan URL must not target link-local metadata addresses", ""
    href = strip_trailing_slashes(f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}")
    return True, href, "https" if parsed.scheme == "https" else "http"


def url_requires_scan_auth(url: str) -> bool:
    try:
        return urllib.parse.urlparse(url).scheme == "https"
    except ValueError:
        return url.startswith("https://")


def has_scan_credentials(auth: ScanAuthConfig) -> bool:
    return bool(auth.oidc or auth.api_key)


def _cache_key_for(oidc: ScanOidcCredentials) -> str:
    return f"{oidc.issuer}|{oidc.client_id}|{oidc.audience}|{oidc.scope}"


def _http_json_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp_headers, resp.read()
    except urllib.error.HTTPError as exc:
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        payload = exc.read() if exc.fp else b""
        return exc.code, resp_headers, payload


def _fetch_token_endpoint(issuer: str, timeout: float = 30.0) -> str:
    discovery_url = f"{strip_trailing_slashes(issuer)}/.well-known/openid-configuration"
    status, _headers, payload = _http_json_request(discovery_url, timeout=timeout)
    if status != 200:
        raise RuntimeError(f"OIDC discovery failed: HTTP {status}")
    doc = json.loads(payload.decode("utf-8"))
    token_endpoint = doc.get("token_endpoint")
    if not isinstance(token_endpoint, str) or not token_endpoint:
        raise RuntimeError("OIDC discovery missing token_endpoint")
    return token_endpoint


def _decode_jwt_exp_ms(access_token: str) -> float | None:
    parts = access_token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            return float(exp) * 1000.0
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None
    return None


def get_scan_access_token(oidc: ScanOidcCredentials, timeout: float = 30.0) -> str:
    global _token_cache
    key = _cache_key_for(oidc)
    now = time.time() * 1000.0
    if (
        _token_cache
        and _token_cache.cache_key == key
        and _token_cache.expires_at_ms > now + TOKEN_EXPIRY_SKEW_SEC * 1000
    ):
        return _token_cache.access_token

    token_endpoint = _fetch_token_endpoint(oidc.issuer, timeout=timeout)
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": oidc.client_id,
            "client_secret": oidc.client_secret,
            "scope": oidc.scope,
            "audience": oidc.audience,
        }
    ).encode("utf-8")
    status, _headers, payload = _http_json_request(
        token_endpoint,
        method="POST",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body=body,
        timeout=timeout,
    )
    response_text = payload.decode("utf-8", errors="replace")
    if status != 200:
        hint = response_text.strip()[:200]
        raise RuntimeError(
            f"client_credentials token mint failed: HTTP {status}" + (f": {hint}" if hint else "")
        )
    try:
        doc = json.loads(response_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("token response was not JSON") from exc
    access_token = doc.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise RuntimeError("token response missing access_token")

    jwt_exp = _decode_jwt_exp_ms(access_token)
    expires_in = doc.get("expires_in")
    expires_in_sec = expires_in if isinstance(expires_in, (int, float)) and expires_in > 0 else 1800
    expires_at_ms = jwt_exp if jwt_exp is not None else now + expires_in_sec * 1000

    _token_cache = _TokenCache(
        access_token=access_token,
        expires_at_ms=expires_at_ms,
        cache_key=key,
    )
    return access_token


def resolve_scan_bearer_token(auth: ScanAuthConfig, timeout: float = 30.0) -> str | None:
    if auth.oidc:
        return get_scan_access_token(auth.oidc, timeout=timeout)
    return auth.api_key


def build_scan_auth_headers(
    auth: ScanAuthConfig,
    extra: dict[str, str] | None = None,
    *,
    timeout: float = 30.0,
) -> dict[str, str]:
    headers = {"content-type": "application/json", **(extra or {})}
    bearer = resolve_scan_bearer_token(auth, timeout=timeout)
    if bearer:
        headers["authorization"] = f"Bearer {bearer}"
    return headers
