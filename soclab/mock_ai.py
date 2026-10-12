from .schema import event


class MockAI:
    """Deterministic contract test double. This is NOT a trained ML model."""
    def predict(self, raw):
        e = event(raw)
        f = e["features"]
        score = round(min(0.99, max(0.10, f["failed_logins_60s"] / 20,
                                  f["unique_dst_ports_60s"] / 50)), 4)
        return {"event_id": e["event_id"], "anomaly_score": score,
                "score_semantics": "higher_is_more_anomalous_0_1",
                "model_version": "mock-deterministic-v1", "is_mock": True}
