import copy
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib import request, error
from soclab.automation import Automation
from soclab.common import APIError, http_json, load_policy
from soclab.mock_ai import MockAI
from soclab.mock_firewall import MockFirewall
from soclab.policy import Policy
from soclab.schema import event
from soclab.server import make_server

ROOT = Path(__file__).resolve().parents[1]


class SOCtests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = 1800000000.0
        self.policy = load_policy(str(ROOT / "config/policy.json"))
        self.ai = MockAI()
        self.fw = MockFirewall(self.policy, Path(self.tmp.name) / "fw.db", lambda: self.now)
        self.auto = Automation(self.policy, Path(self.tmp.name) / "auto.db", self.ai.predict,
                               self.fw.block, False, lambda: self.now)
        self.e = json.loads((ROOT / "examples/01_bruteforce.json").read_text())
        self.e["timestamp"] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()

    def tearDown(self):
        self.auto.conn.close()
        self.fw.conn.close()
        self.tmp.cleanup()

    def assert_error(self, status, call):
        with self.assertRaises(APIError) as caught:
            call()
        self.assertEqual(caught.exception.status, status)

    def test_attack_reaches_mock_alias(self):
        r = self.auto.process(self.e)
        self.assertEqual((r["decision"], r["execution"], r["risk_score"]), ("BLOCK", "mock_applied", 93.3))
        self.assertEqual(self.fw.blocks()["blocks"][0]["ip"], self.e["src_ip"])

    def test_benign_observed(self):
        self.e.update(severity=2, features={"failed_logins_60s": 0, "unique_dst_ports_60s": 1})
        self.assertEqual(self.auto.process(self.e)["decision"], "OBSERVE")
        self.assertEqual(self.fw.blocks()["blocks"], [])

    def test_protected_and_special_addresses(self):
        for n, address in enumerate(["10.10.99.10", "10.10.30.20", "10.10.20.10", "10.10.40.1",
                                     "127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "::1",
                                     "::ffff:10.10.99.10", "fd00::1", "255.255.255.255"]):
            with self.subTest(address=address):
                self.e.update(event_id=str(n), src_ip=address)
                self.assertEqual(self.auto.process(self.e)["decision"], "REVIEW")
                self.assert_error(403, lambda: self.fw.block({"request_id":str(n), "ip":address,"ttl_seconds":10}))
        self.assertEqual(self.fw.blocks()["blocks"], [])

    def test_core_routed_internal_is_review(self):
        self.e["src_ip"] = "10.10.40.25"
        r = self.auto.process(self.e)
        self.assertEqual((r["decision"], r["reason"]), ("REVIEW", "outside_enforcement_scope"))

    def test_fim_does_not_block_source(self):
        self.e["event_type"] = "fim"
        self.assertEqual(self.auto.process(self.e)["decision"], "REVIEW")

    def test_dry_run_no_side_effect(self):
        self.auto.dry_run = True
        self.assertEqual(self.auto.process(self.e)["execution"], "dry_run")
        self.assertEqual(self.fw.blocks()["blocks"], [])

    def test_replay_does_not_extend_ttl(self):
        first = self.auto.process(self.e)
        self.now += 60
        second = self.auto.process(self.e)
        self.assertTrue(second["replayed"])
        self.assertEqual(first["firewall"]["expires_at"], second["firewall"]["expires_at"])
        self.assertEqual(self.fw.conn.execute("SELECT COUNT(*) FROM audit WHERE action='BLOCK'").fetchone()[0], 1)

    def test_conflicting_event_id(self):
        self.auto.process(self.e)
        self.e["src_ip"] = "198.51.100.45"
        self.assert_error(409, lambda: self.auto.process(self.e))

    def test_expire_without_http_request(self):
        self.auto.process(self.e)
        self.now += self.policy.ttl + 1
        self.fw.expire()
        self.assertEqual(self.fw.conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0], 0)

    def test_unblock_is_idempotent(self):
        self.auto.process(self.e)
        for _ in range(2):
            self.assertEqual(self.fw.unblock({"ip": self.e["src_ip"]})["status"], "unblocked")
        self.assertEqual(self.fw.blocks()["blocks"], [])

    def test_ai_failure_no_block(self):
        def fail(_):
            raise APIError(503, "AI offline")
        self.auto.predict = fail
        self.assert_error(503, lambda: self.auto.process(self.e))
        self.assertEqual(self.fw.blocks()["blocks"], [])
        self.assertEqual(self.auto.audit()["records"][0]["decision"], "ERROR")

    def test_invalid_ai_response_rejected(self):
        baseline = self.ai.predict(self.e)
        for patch in [{"anomaly_score": -0.1}, {"anomaly_score": float("nan")}, {"anomaly_score": True},
                      {"event_id": "wrong"}, {"score_semantics": "raw_IF"}, {"model_version": ""}]:
            with self.subTest(patch=patch):
                self.auto.predict = lambda e: dict(baseline, **patch)
                self.assert_error(502, lambda: self.auto.process(self.e))
        self.assertEqual(self.fw.blocks()["blocks"], [])

    def test_timeout_after_firewall_commits_retries_same_request(self):
        def timeout_after_commit(action):
            self.fw.block(action)
            raise APIError(503, "Simulated dropped HTTP response")
        self.auto.block = timeout_after_commit
        self.assert_error(503, lambda: self.auto.process(self.e))
        expiry = self.fw.blocks()["blocks"][0]["expires_at"]
        self.now += 20
        self.auto.block = self.fw.block
        r = self.auto.process(self.e)
        self.assertEqual(r["firewall"]["expires_at"], expiry)
        self.assertTrue(r["firewall"]["replayed"])

    def test_wrong_firewall_ack_never_marked_applied(self):
        self.auto.block = lambda a: {"mode": "real", "status": "blocked"}
        self.assert_error(502, lambda: self.auto.process(self.e))
        self.assertEqual(self.auto.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)

    def test_restart_persists_replay_and_blocks(self):
        first = self.auto.process(self.e)
        self.auto.conn.close()
        self.fw.conn.close()
        self.fw = MockFirewall(self.policy, Path(self.tmp.name) / "fw.db", lambda: self.now)
        self.auto = Automation(self.policy, Path(self.tmp.name) / "auto.db", self.ai.predict,
                               self.fw.block, False, lambda: self.now)
        self.assertTrue(self.auto.process(self.e)["replayed"])
        self.assertEqual(self.fw.blocks()["blocks"][0]["expires_at"], first["firewall"]["expires_at"])

    def test_concurrent_duplicate_only_one_block(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.auto.process(self.e), range(8)))
        self.assertEqual(sum(not r["replayed"] for r in results), 1)
        self.assertEqual(len(self.fw.blocks()["blocks"]), 1)

    def test_missing_src_not_replaced_by_agent_ip(self):
        del self.e["src_ip"]
        self.e["agent"] = {"ip": "10.10.99.10"}
        self.assert_error(422, lambda: self.auto.process(self.e))

    def test_invalid_ip_and_cidr(self):
        for address in ["198.51.100.0/24", "host.example", "bad;command", "fe80::1%eth0"]:
            with self.subTest(address=address):
                self.e["src_ip"] = address
                self.assert_error(422, lambda: self.auto.process(self.e))

    def test_invalid_feature(self):
        for value in [-1, True, 1.5, "30"]:
            with self.subTest(value=value):
                self.e["features"]["failed_logins_60s"] = value
                self.assert_error(422, lambda: self.auto.process(self.e))

    def test_stale_and_future_events(self):
        for delta in [-301, 31]:
            with self.subTest(delta=delta):
                self.e["timestamp"] = datetime.fromtimestamp(self.now+delta, timezone.utc).isoformat()
                self.assert_error(422, lambda: self.auto.process(self.e))

    def test_thresholds_and_minimum_evidence(self):
        e = event(self.e)
        e["severity"] = 10
        self.assertEqual(self.policy.decide(e, 0.85)["decision"], "REVIEW")  # risk 79.5
        self.assertEqual(self.policy.decide(e, 0.86)["decision"], "BLOCK")
        e["severity"] = 15
        self.assertEqual(self.policy.decide(e, 0.84)["decision"], "REVIEW")
        e["severity"] = 9
        self.assertEqual(self.policy.decide(e, 0.99)["decision"], "REVIEW")

    def test_block_cap_and_ttl_validation(self):
        self.policy.data["max_active_blocks"] = 1
        self.auto.process(self.e)
        self.assert_error(429, lambda: self.fw.block({"request_id":"two","ip":"198.51.100.25","ttl_seconds":20}))
        self.assert_error(422, lambda: self.fw.block({"request_id":"two","ip":"198.51.100.25","ttl_seconds":9999}))

    def test_firewall_id_conflict_and_replay_after_expiry(self):
        action = {"request_id":"abc","ip":"198.51.100.23","ttl_seconds":5}
        self.fw.block(action)
        self.assert_error(409, lambda: self.fw.block(dict(action, ip="198.51.100.24")))
        self.now += 6
        self.assertTrue(self.fw.block(action)["replayed"])
        self.assertEqual(self.fw.blocks()["blocks"], [])

    def test_pending_policy_change(self):
        self.auto.block = lambda a: (_ for _ in ()).throw(APIError(503, "offline"))
        self.assert_error(503, lambda: self.auto.process(self.e))
        self.policy.data["version"] = "new-policy"
        self.auto.block = self.fw.block
        self.assertEqual(self.auto.process(self.e)["reason"], "policy_changed_while_pending")
        self.assertEqual(self.fw.blocks()["blocks"], [])

    def test_invalid_policy_refused(self):
        p = copy.deepcopy(self.policy.data)
        p["protected_networks"] = []
        with self.assertRaises(ValueError):
            Policy(p)

    def test_http_three_services_and_auth(self):
        services = [make_server("ai", self.ai, port=0, token="a"),
                    make_server("firewall", self.fw, port=0, token="f")]
        self.auto.predict = lambda e: http_json(f"http://127.0.0.1:{services[0].server_port}/predict", e, "a")
        self.auto.block = lambda a: http_json(f"http://127.0.0.1:{services[1].server_port}/block", a, "f")
        services.append(make_server("automation", self.auto, port=0, token="t"))
        threads = [threading.Thread(target=s.serve_forever, kwargs={"poll_interval":0.05}, daemon=True) for s in services]
        for t in threads:
            t.start()
        try:
            url = f"http://127.0.0.1:{services[2].server_port}"
            r = http_json(url+"/events", self.e, "t")
            self.assertEqual(r["execution"], "mock_applied")
            req = request.Request(url+"/audit")
            with self.assertRaises(error.HTTPError) as caught:
                request.urlopen(req)
            self.assertEqual(caught.exception.code, 401)
            bad = request.Request(url+"/events", data=b'{"x":NaN}',
                                  headers={"Authorization":"Bearer t", "Content-Type":"application/json"})
            with self.assertRaises(error.HTTPError) as caught:
                request.urlopen(bad)
            self.assertEqual(caught.exception.code, 400)
        finally:
            for s in services:
                s.shutdown()
                s.server_close()
            for t in threads:
                t.join()


if __name__ == "__main__":
    unittest.main()
