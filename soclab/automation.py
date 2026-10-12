import json
import threading
import time
from datetime import datetime
from .common import APIError, canonical, db, digest, number
from .schema import event, prediction


class Automation:
    def __init__(self, policy, path, predict, block, dry_run=True, clock=time.time):
        self.policy, self.predict, self.block = policy, predict, block
        self.clock, self.dry_run = clock, dry_run
        self.conn, self.lock = db(path), threading.RLock()
        self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, fingerprint TEXT, response TEXT);
            CREATE TABLE IF NOT EXISTS pending(id TEXT PRIMARY KEY, fingerprint TEXT, decision TEXT, request TEXT);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, time REAL, event_id TEXT, body TEXT);
        ''')

    def _audit(self, eid, value):
        with self.conn:
            self.conn.execute("INSERT INTO audit(time,event_id,body) VALUES(?,?,?)",
                              (self.clock(), eid, canonical(value)))

    def process(self, raw):
        e = event(raw)
        fingerprint, eid = digest(e), e["event_id"]
        # One automation process; serializes dedup + policy + side effect.
        with self.lock:
            prior = self.conn.execute("SELECT fingerprint,response FROM events WHERE id=?", (eid,)).fetchone()
            if prior:
                if prior[0] != fingerprint:
                    raise APIError(409, "event_id reused with different content")
                return dict(json.loads(prior[1]), replayed=True)
            pending = self.conn.execute("SELECT fingerprint,decision,request FROM pending WHERE id=?", (eid,)).fetchone()
            if pending and pending[0] != fingerprint:
                raise APIError(409, "Pending event_id reused with different content")
            age = self.clock() - datetime.fromisoformat(e["timestamp"]).timestamp()
            if age > self.policy.data["max_event_age_seconds"] or age < -self.policy.data["max_future_skew_seconds"]:
                self._audit(eid, {"decision": "REJECT", "reason": "stale_or_future_event"})
                raise APIError(422, "Event outside permitted time window; no new block issued")
            try:
                if pending:
                    result, action = json.loads(pending[1]), json.loads(pending[2])
                    # A changed whitelist must override a previously pending action.
                    guard = self.policy.guard(e["src_ip"])
                    if guard:
                        result.update(decision="REVIEW", reason=guard, execution="none")
                    elif result["policy_version"] != self.policy.data["version"]:
                        result.update(decision="REVIEW", reason="policy_changed_while_pending", execution="none")
                    elif self.dry_run:
                        result.update(execution="dry_run")
                else:
                    ai = prediction(self.predict(e), eid)
                    result = self.policy.decide(e, ai["anomaly_score"])
                    result.update(event_id=eid, model_version=ai["model_version"],
                                  replayed=False, execution="none", mode="mock",
                                  processed_at=self.clock())
                    action = {"request_id": "soc-" + digest({"event": e, "policy": self.policy.data["version"]}),
                              "ip": e["src_ip"], "ttl_seconds": self.policy.ttl}
                    if result["decision"] == "BLOCK":
                        result["execution"] = "dry_run" if self.dry_run else "pending"
                    if result["execution"] == "pending":
                        # Persist exact intent before HTTP; reuse request_id on timeout/restart.
                        with self.conn:
                            self.conn.execute("INSERT INTO pending VALUES(?,?,?,?)",
                                              (eid, fingerprint, canonical(result), canonical(action)))
                if result["decision"] == "BLOCK" and result["execution"] == "pending":
                    ack = self.block(action)
                    if (not isinstance(ack, dict) or ack.get("mode") != "mock"
                            or ack.get("ip") != action["ip"] or ack.get("request_id") != action["request_id"]
                            or ack.get("status") not in ("blocked", "already_blocked")):
                        raise APIError(502, "Firewall acknowledgement mismatch")
                    try:
                        number(ack.get("expires_at"), "expires_at", 0, 1e12)
                    except APIError as exc:
                        raise APIError(502, "Firewall expiry invalid") from exc
                    result.update(execution="mock_applied" if ack["expires_at"] > self.clock() else "mock_expired",
                                  firewall=ack)
                with self.conn:
                    self.conn.execute("INSERT INTO events VALUES(?,?,?)", (eid, fingerprint, canonical(result)))
                    self.conn.execute("DELETE FROM pending WHERE id=?", (eid,))
                    self.conn.execute("INSERT INTO audit(time,event_id,body) VALUES(?,?,?)",
                                      (self.clock(), eid, canonical(result)))
                return result
            except APIError as exc:
                self._audit(eid, {"decision": "ERROR", "reason": exc.message,
                                  "execution": "unknown_if_request_reached_firewall" if self.conn.execute(
                                      "SELECT 1 FROM pending WHERE id=?", (eid,)).fetchone() else "none"})
                raise

    def audit(self):
        with self.lock:
            rows = self.conn.execute("SELECT time,event_id,body FROM audit ORDER BY id DESC LIMIT 100").fetchall()
        return {"records": [{"time": t, "event_id": eid, **json.loads(body)} for t, eid, body in rows]}
