"""Scope guard: the scanner may only touch explicitly allow-listed targets."""
from urllib.parse import urlparse

import config


class ScopeError(ValueError):
    """Raised when a target is not authorized for scanning."""


def validate_target(url: str) -> str:
    """Return a normalized target URL or raise ScopeError."""
    try:
        parsed = urlparse((url or "").strip())
        port = parsed.port
    except ValueError:
        raise ScopeError("Invalid URL.")

    if parsed.scheme not in ("http", "https"):
        raise ScopeError("Only http:// or https:// targets are accepted.")
    if not parsed.hostname:
        raise ScopeError("Target has no hostname.")

    port = port or (443 if parsed.scheme == "https" else 80)
    key = f"{parsed.hostname.lower()}:{port}"
    if key not in config.ALLOWED_TARGETS:
        raise ScopeError(
            f"{key} is not in the authorized target list. "
            "Add it to ALLOWED_TARGETS in config.py only if you own it or have written permission."
        )
    return f"{parsed.scheme}://{key}"


def zap_target(url: str) -> str:
    """Rewrite the target so ZAP (inside Docker) can reach it."""
    if not config.ZAP_IN_DOCKER:
        return url
    parsed = urlparse(url)
    key = f"{parsed.hostname}:{parsed.port}"
    alias = config.DOCKER_HOST_ALIASES.get(key)
    return f"{parsed.scheme}://{alias}" if alias else url
