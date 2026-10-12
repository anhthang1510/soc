import argparse
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from soclab.common import http_json

parser = argparse.ArgumentParser(description="Submit a fresh copy of a sample event")
parser.add_argument("file")
parser.add_argument("--url", default="http://127.0.0.1:8000/events")
parser.add_argument("--keep-id", action="store_true")
parser.add_argument("--keep-time", action="store_true")
args = parser.parse_args()
event = json.loads(Path(args.file).read_text(encoding="utf-8"))
if not args.keep_id:
    event["event_id"] = str(uuid.uuid4())
if not args.keep_time:
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
print(json.dumps(http_json(args.url, event, os.environ.get("SOC_AUTOMATION_TOKEN", "demo-automation-token")), indent=2))
