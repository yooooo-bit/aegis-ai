"""OWASP ZAP integration via its REST API (no extra SDK needed)."""
import time

import requests

import config
from app import scope, settings


class ScannerError(RuntimeError):
    pass


def _api(path: str, **params):
    params["apikey"] = settings.get("zap_api_key")
    try:
        r = requests.get(f"{settings.get('zap_url')}/JSON/{path}/", params=params, timeout=30)
    except requests.RequestException as exc:
        raise ScannerError(f"Cannot reach ZAP at {settings.get('zap_url')}: {exc}") from exc
    if r.status_code >= 400:
        try:
            body = r.json()
            reason = body.get("message") or body.get("code") or r.text[:200]
        except ValueError:
            reason = r.text[:200]
        raise ScannerError(f"ZAP rejected '{path}' (HTTP {r.status_code}): {reason}")
    return r.json()


def _wait(status_path: str, deadline: float, **params):
    while True:
        status = int(_api(status_path, **params)["status"])
        if status >= 100:
            return
        if time.time() > deadline:
            raise ScannerError("Scan exceeded MAX_SCAN_SECONDS and was stopped.")
        time.sleep(2)


def _wait_passive(deadline: float):
    while int(_api("pscan/view/recordsToScan")["recordsToScan"]) > 0:
        if time.time() > deadline:
            raise ScannerError("Passive scan exceeded time limit.")
        time.sleep(2)


def run_scan(target: str, active: bool = False) -> list:
    """Spider the target, wait for passive scan, optionally run active scan.

    `target` must already be validated by app.scope.validate_target().
    Returns a list of normalized finding dicts.
    """
    zap_url = scope.zap_target(target)
    deadline = time.time() + settings.get_int("max_scan_seconds")

    # ZAP's site tree stores the root with a trailing slash; the active scanner needs that exact form.
    zap_root = zap_url.rstrip("/") + "/"

    # Make ZAP load the page first. This puts the site in its tree; an unreachable target raises here.
    _api("core/action/accessUrl", url=zap_root, followRedirects="true")
    for _ in range(8):  # ZAP adds the page to its tree a moment after answering
        if _api("core/view/urls", baseurl=zap_root).get("urls"):
            break
        time.sleep(1)

    spider_id = _api("spider/action/scan", url=zap_root)["scan"]
    _wait("spider/view/status", deadline, scanId=spider_id)
    _wait_passive(deadline)

    if not _api("core/view/urls", baseurl=zap_root).get("urls"):
        raise ScannerError(
            f"ZAP could not load {zap_root} from inside Docker. "
            "Check that juice-shop is running (docker ps), wait a minute, and try again."
        )

    if active:
        ascan_id = _api("ascan/action/scan", url=zap_root, recurse="true")["scan"]
        _wait("ascan/view/status", deadline, scanId=ascan_id)

    alerts = _api("core/view/alerts", baseurl=zap_url, start=0, count=5000)["alerts"]
    return [_normalize(a, zap_url, target) for a in alerts]


def _normalize(alert: dict, zap_url: str, original: str) -> dict:
    return {
        "title": alert.get("alert") or alert.get("name"),
        "risk": alert.get("risk", "Informational"),
        "confidence": alert.get("confidence", "Medium"),
        "url": (alert.get("url") or "").replace(zap_url, original),
        "param": alert.get("param", ""),
        "description": alert.get("description", ""),
        "solution": alert.get("solution", ""),
        "cwe": alert.get("cweid", ""),
        "plugin_id": alert.get("pluginId", ""),
        "evidence": alert.get("evidence", ""),
    }
