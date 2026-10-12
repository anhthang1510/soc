from datetime import datetime, timezone
from .common import APIError, ip, number


def event(raw):
    required = {"event_id", "timestamp", "source", "src_ip", "severity", "event_type", "features"}
    if not isinstance(raw, dict) or not required <= raw.keys() or raw.keys() - required - {"dst_ip"}:
        raise APIError(422, "Invalid event fields; see examples and docs/API.md")
    out = dict(raw)
    if not isinstance(out["event_id"], str) or not 1 <= len(out["event_id"]) <= 128:
        raise APIError(422, "event_id must contain 1..128 characters")
    if out["source"] not in ("wazuh", "suricata", "test"):
        raise APIError(422, "Unsupported source")
    if out["event_type"] not in ("brute_force", "port_scan", "fim", "other"):
        raise APIError(422, "Unsupported event_type")
    out["src_ip"] = ip(out["src_ip"])
    if "dst_ip" in out:
        out["dst_ip"] = ip(out["dst_ip"])
    number(out["severity"], "severity", 0, 15, True)
    try:
        timestamp = datetime.fromisoformat(out["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("Timezone required")
        out["timestamp"] = timestamp.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, AttributeError) as exc:
        raise APIError(422, "timestamp must be ISO 8601 with timezone") from exc
    f = out["features"]
    names = {"failed_logins_60s", "unique_dst_ports_60s"}
    if not isinstance(f, dict) or set(f) != names:
        raise APIError(422, "features must contain failed_logins_60s and unique_dst_ports_60s")
    for name in names:
        number(f[name], name, 0, 1000000, True)
    return out


def prediction(raw, event_id):
    if not isinstance(raw, dict) or raw.get("event_id") != event_id:
        raise APIError(502, "AI response event_id mismatch")
    if raw.get("score_semantics") != "higher_is_more_anomalous_0_1":
        raise APIError(502, "AI score semantics mismatch")
    if not isinstance(raw.get("model_version"), str) or not raw["model_version"]:
        raise APIError(502, "AI model_version missing")
    try:
        number(raw.get("anomaly_score"), "anomaly_score", 0, 1)
    except APIError as exc:
        raise APIError(502, "AI score invalid") from exc
    return raw
