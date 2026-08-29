"""CLI: ``hermes sentrook configure|verify``."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .auth import (
    CLIENT_ID_VAR,
    CLIENT_SECRET_VAR,
    resolve_hermes_state_dir,
)
from .scan_endpoint import DEFAULT_OIDC_ISSUER
from .scan_error_policy import OnScanError, parse_on_scan_error
from .verify import format_verify_report, run_verify

OIDC_ISSUER_VAR = "SENTROOK_OIDC_ISSUER"

PLUGIN_ID = "sentrook"
DEFAULT_TIMEOUT_MS = 60_000
DEFAULT_ON_SCAN_ERROR: OnScanError = "review"
DEFAULT_CONTRIBUTE_CORPUS = True


def _settings_from_ctx(ctx: Any | None) -> dict:
    if ctx is None:
        return {}
    for name in ("get_settings", "settings", "plugin_settings", "get_config"):
        fn = getattr(ctx, name, None)
        if callable(fn):
            try:
                val = fn()
                if isinstance(val, dict):
                    return val
            except TypeError:
                try:
                    val = fn(PLUGIN_ID)
                    if isinstance(val, dict):
                        return val
                except Exception:
                    pass
            except Exception:
                pass
        elif isinstance(fn, dict):
            return fn
    return {}


def _write_dotenv_lines(path: Path, updates: dict[str, str]) -> None:
    existing: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            trimmed = line.strip()
            if not trimmed or trimmed.startswith("#") or "=" not in trimmed:
                continue
            key, _, value = trimmed.partition("=")
            existing[key.strip()] = value.strip()
    existing.update(updates)
    lines = [f"{key}={value}" for key, value in sorted(existing.items())]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


@dataclass(frozen=True)
class ConfigureAnswers:
    client_id: str
    client_secret: str
    timeout_ms: int
    on_scan_error: OnScanError
    contribute_corpus: bool


def feedback_mode_from_contribute(contribute: bool) -> str:
    return "submit" if contribute else "off"


def cmd_configure(args: argparse.Namespace, ctx: Any | None = None) -> int:
    """Write OIDC credentials and plugin settings to Hermes state."""
    state_dir = resolve_hermes_state_dir()
    dotenv_path = state_dir / ".env"
    interactive = not bool(getattr(args, "non_interactive", False))

    answers = _collect_configure_answers(args, interactive=interactive)
    if answers is None:
        return 2

    _write_dotenv_lines(
        dotenv_path,
        {
            CLIENT_ID_VAR: answers.client_id,
            CLIENT_SECRET_VAR: answers.client_secret,
            # Pin issuer to the Identity host that matches this plugin's
            # SCAN_BASE_URL. Override later only if you rebuilt with a different pair.
            OIDC_ISSUER_VAR: DEFAULT_OIDC_ISSUER,
        },
    )
    print(f"Wrote OIDC credentials to {dotenv_path}")
    print(f"  {OIDC_ISSUER_VAR}={DEFAULT_OIDC_ISSUER}")

    settings_written, detail = _update_plugin_settings(
        state_dir=state_dir,
        timeout_ms=answers.timeout_ms,
        on_scan_error=answers.on_scan_error,
        feedback_mode=feedback_mode_from_contribute(answers.contribute_corpus),
    )
    if settings_written:
        print(detail)
    else:
        print(detail, file=sys.stderr)

    print("Then restart the gateway / CLI session and run: hermes sentrook verify")
    return 0


def cmd_verify(args: argparse.Namespace, ctx: Any | None = None) -> int:
    """Check install, enablement, hooks, credentials, health, and OIDC mint."""
    settings = _settings_from_ctx(ctx)
    result = run_verify(
        settings=settings,
        skip_health=bool(getattr(args, "skip_health", False)),
        skip_mint=bool(getattr(args, "skip_mint", False)),
    )
    print(format_verify_report(result))
    return 0 if result.ok else 1


def _handler(args: argparse.Namespace) -> None:
    ctx = getattr(args, "_plugin_ctx", None)
    sub = getattr(args, "sentrook_command", None)
    if sub == "configure":
        raise SystemExit(cmd_configure(args, ctx))
    if sub == "verify":
        raise SystemExit(cmd_verify(args, ctx))
    print("Usage: hermes sentrook <configure|verify>", file=sys.stderr)
    raise SystemExit(2)


def setup_argparse(subparser: argparse.ArgumentParser) -> None:
    subs = subparser.add_subparsers(dest="sentrook_command")
    configure = subs.add_parser(
        "configure",
        help="Interactive setup for Sentrook OIDC credentials and plugin settings",
    )
    configure.add_argument("--client-id", help="OIDC client id (or use env)")
    configure.add_argument("--client-secret", help="OIDC client secret")
    configure.add_argument(
        "--timeout-ms",
        type=int,
        help=f"Scan timeout in ms (default {DEFAULT_TIMEOUT_MS})",
    )
    configure.add_argument(
        "--on-scan-error",
        choices=["allow", "deny", "review"],
        help=f"Policy when /scan fails (default: {DEFAULT_ON_SCAN_ERROR})",
    )
    configure.add_argument(
        "--contribute-corpus",
        choices=["true", "false"],
        help="Contribute sanitized review feedback to the community corpus (default true)",
    )
    configure.add_argument(
        "--non-interactive",
        action="store_true",
        help="Require explicit flags/env values; do not prompt",
    )
    verify = subs.add_parser(
        "verify",
        help="Check install, enablement, hooks, credentials, and scan reachability",
    )
    verify.add_argument("--skip-health", action="store_true", help="Skip GET /health")
    verify.add_argument(
        "--skip-mint",
        action="store_true",
        help="Skip OIDC client_credentials token mint",
    )
    subparser.set_defaults(func=_handler)


def register_cli(ctx: Any) -> None:
    def handler_with_ctx(args: argparse.Namespace) -> None:
        args._plugin_ctx = ctx
        _handler(args)

    ctx.register_cli_command(
        name="sentrook",
        help="Sentrook scan plugin — configure and verify",
        description="Manage the Sentrook Hermes plugin",
        setup_fn=setup_argparse,
        handler_fn=handler_with_ctx,
    )


def _prompt_text(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{label}{suffix}: ").strip()
    if raw:
        return raw
    return default or ""


def _prompt_secret(label: str) -> str:
    return getpass.getpass(f"{label}: ").strip()


def _prompt_confirm(label: str, default_yes: bool = True) -> bool:
    hint = "Y/n" if default_yes else "y/N"
    raw = input(f"{label} [{hint}]: ").strip().lower()
    if not raw:
        return default_yes
    return raw in ("y", "yes")


def _parse_contribute(raw: Any, default: bool = DEFAULT_CONTRIBUTE_CORPUS) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        value = raw.strip().lower()
        if value in ("1", "true", "yes", "on", "submit"):
            return True
        if value in ("0", "false", "no", "off"):
            return False
    return default


def _collect_configure_answers(
    args: argparse.Namespace, *, interactive: bool
) -> ConfigureAnswers | None:
    client_id = (getattr(args, "client_id", None) or os.environ.get(CLIENT_ID_VAR, "")).strip()
    client_secret = (
        getattr(args, "client_secret", None) or os.environ.get(CLIENT_SECRET_VAR, "")
    ).strip()

    timeout_ms = getattr(args, "timeout_ms", None)
    timeout_ms = (
        timeout_ms if isinstance(timeout_ms, int) and timeout_ms > 0 else DEFAULT_TIMEOUT_MS
    )

    on_scan_error_raw = getattr(args, "on_scan_error", None) or os.environ.get(
        "SENTROOK_ON_SCAN_ERROR", ""
    )
    on_scan_error = parse_on_scan_error(on_scan_error_raw, DEFAULT_ON_SCAN_ERROR)

    contribute_raw = getattr(args, "contribute_corpus", None)
    if contribute_raw is None:
        feedback_env = os.environ.get("SENTROOK_FEEDBACK_MODE", "").strip().lower()
        if feedback_env in ("off", "false", "0", "no"):
            contribute_raw = "false"
        elif feedback_env in ("submit", "queue", "true", "1", "yes", "on"):
            contribute_raw = "true"
    contribute_corpus = _parse_contribute(contribute_raw, DEFAULT_CONTRIBUTE_CORPUS)

    if interactive:
        if not (client_id and client_secret):
            print("")
            print("==> Scan auth (OIDC client credentials)")
            print("    To use the hosted Sentrook instance, you need a free FIDU membership")
            print("    with a Sentrook OAuth client.")
            print("")
            print(f"    Visit {DEFAULT_OIDC_ISSUER} and log in or create an")
            print("    account (free membership is all that's required).")
            print("    On your dashboard, click the Sentrook tab.")
            print("    Click 'Create Credentials'")
            print("    Paste the client_id and client_secret when prompted below.")
            client_id = _prompt_text("OAuth client_id")
            client_secret = _prompt_secret("OAuth client_secret")

        if getattr(args, "timeout_ms", None) is None:
            if not _prompt_confirm(f"Use default timeout ({DEFAULT_TIMEOUT_MS}ms)?", True):
                timeout_raw = _prompt_text("Timeout ms", str(DEFAULT_TIMEOUT_MS))
                try:
                    parsed_timeout = int(timeout_raw)
                    if parsed_timeout > 0:
                        timeout_ms = parsed_timeout
                except ValueError:
                    pass

        if getattr(args, "contribute_corpus", None) is None:
            print("")
            print("==> Community corpus")
            print("    When you allow or deny a Sentrook review, a sanitized trajectory")
            print("    example can be submitted to the community corpus, making the tool")
            print(
                "    more useful for everyone. Humans still approve before anything is published."
            )
            print("    Secrets/PII are redacted and submissions are completely anonymous; ")
            print("    you can change this later in config.yaml.")
            contribute_corpus = _prompt_confirm(
                "Contribute review feedback to the community corpus? (opt out with n)",
                True,
            )

        if getattr(args, "on_scan_error", None) is None:
            print("")
            print("==> When Sentrook cannot scan (unreachable, timeout, rate-limit, auth)")
            print("    allow  = continue without scanning (risky; auth failures still block)")
            print("    deny   = block the tool (most secure)")
            print("    review = ask you first (recommended; default)")
            on_scan_error = parse_on_scan_error(
                _prompt_text(f"onScanError [{on_scan_error}]", on_scan_error),
                on_scan_error,
            )

    if not (client_id and client_secret):
        print(
            "sentrook configure: provide --client-id + --client-secret "
            "(or set the required credential environment variables).\n"
            "Use --non-interactive only when flags/env are already set.",
            file=sys.stderr,
        )
        return None

    return ConfigureAnswers(
        client_id=client_id,
        client_secret=client_secret,
        timeout_ms=timeout_ms,
        on_scan_error=on_scan_error,
        contribute_corpus=contribute_corpus,
    )


def _update_plugin_settings(
    *,
    state_dir: Path,
    timeout_ms: int,
    on_scan_error: OnScanError,
    feedback_mode: str,
) -> tuple[bool, str]:
    cfg_path = state_dir / "config.yaml"
    try:
        import yaml  # type: ignore
    except Exception:
        return (
            False,
            "Could not update config.yaml automatically (PyYAML unavailable). "
            "Set plugins.entries.sentrook.settings manually.",
        )

    cfg: dict[str, Any] = {}
    if cfg_path.is_file():
        try:
            loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cfg = loaded
        except Exception as exc:
            return (False, f"Could not parse {cfg_path}: {exc}")

    plugins = cfg.get("plugins")
    if not isinstance(plugins, dict):
        plugins = {}
        cfg["plugins"] = plugins

    enabled = plugins.get("enabled")
    if not isinstance(enabled, list):
        enabled = []
        plugins["enabled"] = enabled
    if PLUGIN_ID not in enabled:
        enabled.append(PLUGIN_ID)

    disabled = plugins.get("disabled")
    if isinstance(disabled, list) and PLUGIN_ID in disabled:
        plugins["disabled"] = [x for x in disabled if x != PLUGIN_ID]

    entries = plugins.get("entries")
    if not isinstance(entries, dict):
        entries = {}
        plugins["entries"] = entries

    entry = entries.get(PLUGIN_ID)
    if not isinstance(entry, dict):
        entry = {}
        entries[PLUGIN_ID] = entry
    entry["enabled"] = True

    settings = entry.get("settings")
    if not isinstance(settings, dict):
        settings = {}
        entry["settings"] = settings

    settings["timeout_ms"] = timeout_ms
    settings["on_scan_error"] = on_scan_error
    settings["feedback_mode"] = feedback_mode
    # Never agent-/config-retargetable (exfil vector).
    settings.pop("scan_base_url", None)

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    return (True, f"Updated plugin settings in {cfg_path} (enabled + settings).")
