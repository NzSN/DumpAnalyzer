#!/usr/bin/python3
"""Load Claude connection/model settings without enabling its other settings."""

import json
import os
from pathlib import Path
import sys


ALLOWED_ENV = frozenset(
    {
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "ANTHROPIC_MODEL",
        "API_TIMEOUT_MS",
        "CLAUDE_CODE_MAX_CONTEXT_TOKENS",
    }
    | {
        f"ANTHROPIC_DEFAULT_{family}_{suffix}"
        for family in ("OPUS", "SONNET", "HAIKU")
        for suffix in ("MODEL", "MODEL_NAME")
    }
)


class SettingsError(ValueError):
    """A configuration problem whose message contains no setting values."""


def reject_json_constant(_value):
    raise ValueError("nonstandard JSON constant")


def build_environment(settings, inherited):
    if not isinstance(settings, dict):
        raise SettingsError("Claude settings must be a JSON object")
    configured = settings.get("env", {})
    if not isinstance(configured, dict):
        raise SettingsError("Claude settings.env must be an object")
    if any(not isinstance(value, str) for value in configured.values()):
        raise SettingsError("Claude settings.env values must be strings")
    selected = {key: value for key, value in configured.items() if key in ALLOWED_ENV}
    if any("\0" in value for value in selected.values()):
        raise SettingsError("Claude connection/model settings cannot contain null bytes")
    if "model" in settings:
        model = settings["model"]
        if not isinstance(model, str) or not model.strip() or "\0" in model:
            raise SettingsError("Claude settings.model must be a nonempty string without null bytes")
    environment = dict(inherited)
    environment.update(selected)
    # An explicit model environment variable takes precedence over the
    # top-level default, including an explicit inherited model override.
    if "ANTHROPIC_MODEL" not in environment and "model" in settings:
        environment["ANTHROPIC_MODEL"] = settings["model"]
    environment.update(
        DISABLE_TELEMETRY="1",
        DISABLE_ERROR_REPORTING="1",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
    )
    return environment


def main(home=None, argv=None):
    home = Path.home() if home is None else Path(home)
    argv = sys.argv[1:] if argv is None else argv
    try:
        try:
            text = (home / ".claude/settings.json").read_text(encoding="utf-8")
        except UnicodeError:
            raise SettingsError("~/.claude/settings.json must contain UTF-8 JSON") from None
        except OSError:
            raise SettingsError("cannot read ~/.claude/settings.json") from None
        try:
            settings = json.loads(text, parse_constant=reject_json_constant)
        except (ValueError, RecursionError):
            raise SettingsError("~/.claude/settings.json must contain valid JSON") from None
        environment = build_environment(settings, os.environ)
    except SettingsError as error:
        print(f"dump-analyzer Claude settings: {error}", file=sys.stderr)
        return 2
    executable = home / ".local/bin/claude"
    try:
        os.execve(str(executable), [str(executable), *argv], environment)
    except (OSError, ValueError, UnicodeError):
        print(
            "dump-analyzer Claude settings: cannot execute ~/.local/bin/claude; "
            "check its installation and permissions",
            file=sys.stderr,
        )
        return 127


if __name__ == "__main__":
    sys.exit(main())
