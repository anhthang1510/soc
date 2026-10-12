import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .automation import Automation
from .common import APIError, canonical, http_json, load_policy
from .mock_ai import MockAI
from .mock_firewall import MockFirewall


def make_app(service, policy=None, data_dir=None, dry_run=None):
    policy = policy or load_policy()
    root = Path(data_dir or os.environ.get("SOC_DATA_DIR", "data"))
    if service == "ai":
        return MockAI()
    if service == "firewall":
        return MockFirewall(policy, root / "firewall.sqlite3")
    if service != "automation":
        raise ValueError("Unknown service")
    if os.environ.get("SOC_FIREWALL_MODE", "mock") != "mock":
        raise ValueError("This package only implements mock firewall mode")
    if dry_run is None:
        mode = os.environ.get("SOC_DRY_RUN", "true").lower()
        if mode not in ("true", "false"):
            raise ValueError("SOC_DRY_RUN must be true or false")
        dry_run = mode == "true"
    ai_url = os.environ.get("SOC_AI_URL", "http://127.0.0.1:8001")
    fw_url = os.environ.get("SOC_FIREWALL_URL", "http://127.0.0.1:8002")
    ai_token = os.environ.get("SOC_AI_TOKEN", "demo-ai-token")
    fw_token = os.environ.get("SOC_FIREWALL_TOKEN", "demo-firewall-token")
    return Automation(policy, root / "automation.sqlite3",
                      lambda e: http_json(ai_url + "/predict", e, ai_token),
                      lambda a: http_json(fw_url + "/block", a, fw_token), dry_run)


def make_server(service, app, host="127.0.0.1", port=8000, token=None):
    token = token or os.environ.get("SOC_" + service.upper() + "_TOKEN", "demo-" + service + "-token")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # Never log Authorization or raw attacker-controlled event content.

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def send(self, status, body):
            data = canonical(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def handle_api(self):
            try:
                if self.command == "GET" and self.path == "/health":
                    self.send(200, {"status": "ok", "service": service, "mode": "mock"})
                    return
                supplied = self.headers.get("Authorization", "").encode()
                if not hmac.compare_digest(supplied, ("Bearer " + token).encode()):
                    raise APIError(401, "Invalid service token")
                if self.command == "GET":
                    if service == "firewall" and self.path == "/blocks":
                        result = app.blocks()
                    elif service == "automation" and self.path == "/audit":
                        result = app.audit()
                    else:
                        raise APIError(404, "Unknown endpoint")
                else:
                    if self.headers.get("Transfer-Encoding"):
                        raise APIError(400, "Transfer-Encoding unsupported in lab API")
                    try:
                        size = int(self.headers.get("Content-Length", "0"))
                    except ValueError as exc:
                        raise APIError(400, "Invalid Content-Length") from exc
                    if not 0 < size <= 65536:
                        raise APIError(413, "Body must be 1..65536 bytes")
                    if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                        raise APIError(415, "Use application/json")
                    try:
                        raw = json.loads(self.rfile.read(size), parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
                    except (ValueError, UnicodeDecodeError) as exc:
                        raise APIError(400, "Malformed JSON") from exc
                    routes = {"ai": {"/predict": "predict"},
                              "firewall": {"/block": "block", "/unblock": "unblock"},
                              "automation": {"/events": "process"}}
                    method = routes[service].get(self.path)
                    if not method:
                        raise APIError(404, "Unknown endpoint")
                    result = getattr(app, method)(raw)
                self.send(200, result)
            except APIError as exc:
                self.send(exc.status, {"error": exc.message, "service": service})
            except (TimeoutError, ConnectionError):
                self.close_connection = True
            except Exception:
                self.send(500, {"error": "Internal lab service error", "service": service})

        do_GET = handle_api
        do_POST = handle_api

    class Server(ThreadingHTTPServer):
        daemon_threads = True

        def service_actions(self):
            if service == "firewall":
                app.expire()

    return Server((host, port), Handler)
