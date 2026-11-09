"""Central configuration for AEGIS AI."""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "aegis.db")

# --- OWASP ZAP daemon (started by docker-compose) ---
ZAP_URL = os.environ.get("ZAP_URL", "http://127.0.0.1:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "changeme")

# --- Scope guard: ONLY these host:port pairs can ever be scanned ---
ALLOWED_TARGETS = {
    "localhost:3000",   # OWASP Juice Shop (docker-compose)
    "127.0.0.1:3000",
}

# ZAP runs inside Docker, so "localhost" must be rewritten to the container name
# before the URL is handed to ZAP. Set ZAP_IN_DOCKER=0 if you run ZAP on your host.
ZAP_IN_DOCKER = os.environ.get("ZAP_IN_DOCKER", "1") == "1"
DOCKER_HOST_ALIASES = {
    "localhost:3000": "juice-shop:3000",
    "127.0.0.1:3000": "juice-shop:3000",
}

MAX_SCAN_SECONDS = 900          # hard stop for any single scan
IS_INTERNET_EXPOSED = False     # lab targets are local; used by the prioritizer

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
