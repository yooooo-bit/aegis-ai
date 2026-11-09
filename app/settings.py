"""Runtime settings stored in SQLite, falling back to the defaults in config.py.

The scan allow-list (ALLOWED_TARGETS) is deliberately NOT a runtime setting: authorizing a new
target must be a conscious edit of config.py, not a click in the web UI.
"""
import re
import sqlite3
from urllib.parse import urlparse

import config
from app import db

LOCAL_HOSTS = {"127.0.0.1", "localhost"}
SECRET_KEYS = {"zap_api_key"}


def defaults() -> dict:
    return {
        "zap_url": config.ZAP_URL,
        "zap_api_key": config.ZAP_API_KEY,
        "max_scan_seconds": str(config.MAX_SCAN_SECONDS),
        "internet_exposed": "1" if config.IS_INTERNET_EXPOSED else "0",
        "ai_mode": "rules",
        "ollama_url": "http://127.0.0.1:11434",
        "ollama_model": "llama3.2",
        "org_name": "",
        "tester_name": "",
    }


def get(key: str) -> str:
    try:
        with db.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if row is not None:
            return row["value"]
    except sqlite3.Error:
        pass  # database or table not ready yet: use the default
    return defaults()[key]


def get_int(key: str) -> int:
    try:
        return int(get(key))
    except ValueError:
        return int(defaults()[key])


def get_bool(key: str) -> bool:
    return get(key) == "1"


def get_all() -> dict:
    return {k: get(k) for k in defaults()}


def save(values: dict) -> list:
    """Persist known keys; return the list of keys that actually changed."""
    known = defaults()
    changed = []
    with db.connect() as conn:
        for key, value in values.items():
            if key not in known:
                continue
            if get(key) != value:
                changed.append(key)
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
    return changed


def _local_url(value: str, label: str, errors: list) -> str:
    value = (value or "").strip().rstrip("/")
    try:
        parsed = urlparse(value)
        ok = parsed.scheme in ("http", "https") and parsed.hostname in LOCAL_HOSTS
    except ValueError:
        ok = False
    if not ok:
        errors.append(f"{label} must be a local address such as http://127.0.0.1:8080 (this tool only talks to your own machine).")
    return value


def validate(form) -> tuple:
    """Validate the settings form. Returns (clean_values, errors)."""
    errors, clean = [], {}

    clean["zap_url"] = _local_url(form.get("zap_url"), "ZAP URL", errors)
    key = (form.get("zap_api_key") or "").strip()
    if key:  # blank means "keep the current key"
        clean["zap_api_key"] = key

    try:
        seconds = int(form.get("max_scan_seconds", ""))
        if not 60 <= seconds <= 3600:
            raise ValueError
        clean["max_scan_seconds"] = str(seconds)
    except ValueError:
        errors.append("Scan time limit must be a whole number between 60 and 3600 seconds.")

    clean["internet_exposed"] = "1" if form.get("internet_exposed") == "on" else "0"

    mode = form.get("ai_mode", "rules")
    if mode not in ("rules", "ollama"):
        errors.append("AI mode must be 'rules' or 'ollama'.")
    clean["ai_mode"] = mode

    clean["ollama_url"] = _local_url(form.get("ollama_url"), "Ollama URL", errors)
    model = (form.get("ollama_model") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,60}", model):
        errors.append("Ollama model name can only contain letters, numbers and . _ : / -")
    clean["ollama_model"] = model

    for field, label in (("org_name", "Organisation"), ("tester_name", "Prepared by")):
        value = (form.get(field) or "").strip()
        if len(value) > 80:
            errors.append(f"{label} must be 80 characters or fewer.")
        clean[field] = value[:80]

    return clean, errors
