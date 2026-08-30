import pytest

pytest.importorskip("fastapi", reason="needs the service extra")

from fastapi.testclient import TestClient  # noqa: E402

from service import app as app_module  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "DB_PATH", str(tmp_path / "test.db"))
    with TestClient(app_module.app) as c:
        yield c


def _send(client, n, start=0, **overrides):
    body = {
        "sender": "a1",
        "recipient": "tool-search",
        "intent": "core",
        "action": "query",
    }
    body.update(overrides)
    last = None
    for i in range(start, start + n):
        # An envelope with no audit proof is itself mildly suspicious, so
        # supply one unless a test is deliberately withholding it.
        payload = {"audit_proof": f"merkle:{i}", **body, "timestamp": float(i)}
        last = client.post("/observe", json=payload)
        assert last.status_code == 200, last.text
    return last.json()


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["shadow"] is True


def test_observe_returns_a_decision(client):
    decision = _send(client, 1)
    assert decision["agent_id"] == "a1"
    assert decision["action"] == "observe"
    assert 0.0 <= decision["p"] <= 1.0


def test_clean_traffic_leaves_the_agent_trusted(client):
    decision = _send(client, 150)
    assert decision["trust"] > 0.9
    assert decision["action"] == "observe"


def test_bad_envelopes_trigger_a_verification(client):
    _send(client, 120)
    _send(
        client,
        60,
        start=120,
        recipient="tool-exfil",
        action="bulk_export",
        signature_valid=False,
        credential_valid=False,
    )
    verifications = client.get("/decisions", params={"action": "verify"}).json()
    assert verifications
    assert verifications[0]["reason"] == "below_threshold"


def test_agents_endpoint_lists_the_fleet(client):
    _send(client, 30)
    _send(client, 30, start=30, sender="a2")
    agents = client.get("/agents").json()
    assert {a["agent_id"] for a in agents} == {"a1", "a2"}


def test_unknown_agent_is_a_404(client):
    assert client.get("/agents/nobody").status_code == 404


def test_trajectory_is_oldest_first(client):
    _send(client, 40)
    points = client.get("/agents/a1/trajectory").json()
    assert len(points) == 40
    assert points[0]["timestamp"] < points[-1]["timestamp"]


def test_metrics_omit_ground_truth_measures(client):
    """Exposure needs labels a live deployment does not have."""
    _send(client, 20)
    metrics = client.get("/metrics").json()
    assert metrics["steps"] == 20
    assert "exposure" not in metrics
    assert "containment" not in metrics
    assert metrics["reasons"]["trusted"] > 0


def test_config_round_trips(client):
    updated = client.put(
        "/config", json={"recovery_seconds": 3600, "theta_low": 0.45}
    ).json()
    assert updated["recovery_seconds"] == 3600
    assert updated["theta_low"] == 0.45
    assert client.get("/config").json()["theta_low"] == 0.45


def test_config_rejects_an_inverted_hysteresis_band(client):
    assert client.put("/config", json={"theta_low": 0.9}).status_code == 422


def test_reconfiguring_preserves_trust_state(client):
    before = _send(client, 120)["trust"]
    client.put("/config", json={"theta_low": 0.45})
    after = client.get("/agents/a1").json()["trust"]
    assert after == pytest.approx(before)


def test_reset_clears_everything(client):
    _send(client, 20)
    assert client.post("/reset").json()["status"] == "cleared"
    assert client.get("/agents").json() == []
    assert client.get("/metrics").json()["steps"] == 0


def test_benchmark_reports_ground_truth_metrics(client):
    body = client.post("/benchmark", json={"sessions": 60, "seed": 0}).json()
    names = {r["policy"] for r in body["results"]}
    assert names == {"beta-trust", "raw-threshold", "ewma-threshold", "periodic"}
    for result in body["results"]:
        assert 0.0 <= result["exposure"] <= 1.0
        assert result["episodes"] > 0


def test_benchmark_can_return_confidence_intervals(client):
    body = client.post(
        "/benchmark", json={"sessions": 40, "seed": 0, "resamples": 50}
    ).json()
    for result in body["results"]:
        lo, hi = result["exposure_ci"]
        assert lo <= result["exposure"] <= hi


def test_frontier_shows_adaptive_costing_less_than_periodic(client):
    points = client.post("/frontier", json={"sessions": 200, "seed": 0}).json()["points"]
    adaptive = [p for p in points if p["policy"] == "adaptive"]
    periodic = [p for p in points if p["policy"] == "periodic"]
    assert adaptive and periodic

    # At comparable exposure, the adaptive policy spends far less.
    best_adaptive = min(adaptive, key=lambda p: p["exposure"])
    matched = [p for p in periodic if p["exposure"] <= best_adaptive["exposure"]]
    assert matched
    assert min(p["budget_per_1k_steps"] for p in matched) > (
        3 * best_adaptive["budget_per_1k_steps"]
    )


def test_feed_autotunes_the_step_interval(client):
    """Without this the trigger never fires; see TrustParams.from_event_interval."""
    client.post(
        "/feed/start",
        json={"agents": 10, "steps_per_second": 100, "auto_tune": True},
    )
    try:
        config = client.get("/config").json()
        assert config["step_seconds"] == pytest.approx(10 / 100)
        assert config["cooldown_seconds"] == pytest.approx(8 * 10 / 100)
    finally:
        client.post("/feed/stop")


def test_feed_can_be_started_and_stopped(client):
    started = client.post("/feed/start", json={"agents": 4, "steps_per_second": 50}).json()
    assert started["running"] is True
    assert client.post("/feed/stop").json()["running"] is False


def test_ingest_rejects_a_non_object_payload(client):
    assert client.post("/ingest/samacp", json=[1, 2, 3]).status_code == 422


def test_ingest_rejects_an_envelope_without_a_sender(client):
    assert client.post("/ingest/samacp", json={"to": "b"}).status_code == 422


def test_decisions_can_be_filtered_by_reason(client):
    """Server-side filtering, because a client can only filter what it saw live."""
    _send(client, 120)
    _send(
        client,
        60,
        start=120,
        recipient="tool-exfil",
        action="bulk_export",
        signature_valid=False,
        credential_valid=False,
    )

    below = client.get("/decisions", params={"reason": "below_threshold"}).json()
    assert below and all(d["reason"] == "below_threshold" for d in below)

    suppressed = client.get(
        "/decisions", params={"reason": "cooldown,budget_exhausted"}
    ).json()
    assert all(d["reason"] in {"cooldown", "budget_exhausted"} for d in suppressed)

    assert client.get("/decisions", params={"reason": "nonsense"}).json() == []
