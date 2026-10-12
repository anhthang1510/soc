"""One-command HTTP demo; ephemeral SQLite so reruns have clean state."""
import argparse
import json
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from soclab.automation import Automation
from soclab.common import http_json, load_policy
from soclab.mock_ai import MockAI
from soclab.mock_firewall import MockFirewall
from soclab.server import make_server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute-mock", action="store_true", help="Apply blocks to simulated SQLite alias")
    args = parser.parse_args()
    policy = load_policy(str(Path(__file__).parent / "config/policy.json"))
    with tempfile.TemporaryDirectory() as folder:
        ai, fw = MockAI(), MockFirewall(policy, Path(folder) / "fw.db")
        ai_server = make_server("ai", ai, port=0, token="demo-ai-token")
        fw_server = make_server("firewall", fw, port=0, token="demo-firewall-token")
        ai_url = f"http://127.0.0.1:{ai_server.server_port}"
        fw_url = f"http://127.0.0.1:{fw_server.server_port}"
        auto = Automation(policy, Path(folder) / "auto.db",
                          lambda e: http_json(ai_url + "/predict", e, "demo-ai-token"),
                          lambda a: http_json(fw_url + "/block", a, "demo-firewall-token"),
                          dry_run=not args.execute_mock)
        auto_server = make_server("automation", auto, port=0, token="demo-automation-token")
        servers = [ai_server, fw_server, auto_server]
        threads = [threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True) for s in servers]
        for thread in threads:
            thread.start()
        try:
            base = f"http://127.0.0.1:{auto_server.server_port}"
            first = None
            for file in sorted((Path(__file__).parent / "examples").glob("*.json")):
                event = json.loads(file.read_text())
                event["timestamp"] = datetime.now(timezone.utc).isoformat()
                if first is None:
                    first = event
                result = http_json(base + "/events", event, "demo-automation-token")
                print(json.dumps({"example": file.name, **result}, ensure_ascii=False))
            result = http_json(base + "/events", first, "demo-automation-token")
            print(json.dumps({"example": "replay_first_event", **result}))
            print(json.dumps(http_json(fw_url + "/blocks", token="demo-firewall-token")))
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join()
            auto.conn.close()
            fw.conn.close()


if __name__ == "__main__":
    main()
