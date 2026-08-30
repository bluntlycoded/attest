import pytest

pytest.importorskip("fastapi", reason="needs the service extra")

from fastapi.testclient import TestClient  # noqa: E402

from service import app as app_module  # noqa: E402


BOOTSTRAP = "attest-test-bootstrap-key"


@pytest.fixture
def client(tmp_path, monkeypatch):
    """An authenticated admin client for the default tenant.

    The service has no anonymous path, so every fixture has to present a
    credential. The bootstrap token comes from the environment rather than a
    row, which is what keeps an unconfigured database unusable rather than
    open.
    """
    monkeypatch.setattr(app_module, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(app_module, "BOOTSTRAP_TOKEN", BOOTSTRAP)
    with TestClient(
        app_module.app, headers={"Authorization": f"Bearer {BOOTSTRAP}"}
    ) as c:
        yield c


@pytest.fixture
def anon(tmp_path, monkeypatch):
    """A client with no credential at all."""
    monkeypatch.setattr(app_module, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(app_module, "BOOTSTRAP_TOKEN", BOOTSTRAP)
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


# -------------------------------------------------------------------- gateway


def _settle_gateway(client, n=60, agent="agent-7"):
    for i in range(n):
        client.post(
            "/gateway/evaluate",
            json={"agent_id": agent, "tool": "search", "timestamp": float(i)},
        )


def test_catalog_is_readable_and_declarable(client):
    assert "wire_transfer" in client.get("/catalog").json()["tools"]
    body = client.put(
        "/catalog/custom_tool",
        json={"reversibility": "reversible", "magnitude": 0.1, "description": "safe"},
    ).json()
    assert body["tools"]["custom_tool"]["magnitude"] == 0.1


def test_a_routine_call_is_allowed(client):
    _settle_gateway(client)
    body = client.post(
        "/gateway/evaluate",
        json={"agent_id": "agent-7", "tool": "search", "timestamp": 100.0},
    ).json()
    assert body["verdict"] == "allow"
    assert body["tier"] == "auto"


def test_a_consequential_call_is_held_with_a_packet(client):
    _settle_gateway(client)
    body = client.post(
        "/gateway/evaluate",
        json={"agent_id": "agent-7", "tool": "wire_transfer", "timestamp": 100.0},
    ).json()

    assert body["verdict"] == "hold"
    assert body["request_id"]
    assert body["packet"]["reversibility"] == "irreversible"


def test_a_held_call_appears_in_the_queue_and_can_be_answered(client):
    _settle_gateway(client)
    held = client.post(
        "/gateway/evaluate",
        json={"agent_id": "agent-7", "tool": "wire_transfer", "timestamp": 100.0},
    ).json()

    pending = client.get("/approvals").json()
    assert [p["request_id"] for p in pending] == [held["request_id"]]
    assert "wire_transfer" in pending[0]["rendered"]

    decided = client.post(
        f"/approvals/{held['request_id']}/decide",
        json={"approver": "alice", "outcome": "approved", "at": 130.0},
    ).json()
    assert decided["outcome"] == "approved"
    assert client.get("/approvals").json() == []


def test_answering_twice_is_a_conflict(client):
    _settle_gateway(client)
    held = client.post(
        "/gateway/evaluate",
        json={"agent_id": "agent-7", "tool": "wire_transfer", "timestamp": 100.0},
    ).json()
    body = {"approver": "alice", "outcome": "approved", "at": 130.0}
    assert client.post(f"/approvals/{held['request_id']}/decide", json=body).status_code == 200
    assert client.post(f"/approvals/{held['request_id']}/decide", json=body).status_code == 409


def test_answering_an_unknown_request_is_a_404(client):
    assert (
        client.post(
            "/approvals/apr-999999/decide",
            json={"approver": "alice", "outcome": "approved"},
        ).status_code
        == 404
    )
    assert client.get("/approvals/apr-999999").status_code == 404


def test_an_mcp_request_is_judged_and_cannot_name_its_own_caller(client):
    _settle_gateway(client)
    body = client.post(
        "/gateway/mcp?agent_id=agent-7",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "wire_transfer",
                "arguments": {"agent_id": "admin", "target": "acct-9"},
            },
        },
    ).json()

    assert body["verdict"] == "hold"
    assert body["packet"]["agent_id"] == "agent-7"


def test_mcp_endpoint_rejects_a_non_object_payload(client):
    assert client.post("/gateway/mcp?agent_id=a", json=[1, 2]).status_code == 422


def test_sweeping_expires_holds_into_denials(client):
    _settle_gateway(client)
    client.post(
        "/gateway/evaluate",
        json={"agent_id": "agent-7", "tool": "wire_transfer", "timestamp": 100.0},
    )
    swept = client.post("/approvals/sweep").json()
    assert swept["expired"]
    assert swept["counts"]["timeout"] >= 1


def test_approver_stats_are_reported(client):
    _settle_gateway(client)
    for i in range(25):
        held = client.post(
            "/gateway/evaluate",
            json={
                "agent_id": "agent-7",
                "tool": "wire_transfer",
                "timestamp": 100.0 + i * 20,
            },
        ).json()
        if held.get("request_id"):
            client.post(
                f"/approvals/{held['request_id']}/decide",
                json={
                    "approver": "clicker",
                    "outcome": "approved",
                    "at": 101.0 + i * 20,
                },
            )

    stats = client.get("/approvers").json()
    assert stats and stats[0]["approver"] == "clicker"


def test_an_out_of_order_timestamp_is_a_client_error_not_a_crash(client):
    """Evidence has to arrive in order; say so rather than returning a 500."""
    _settle_gateway(client)
    response = client.post(
        "/gateway/evaluate",
        json={"agent_id": "agent-7", "tool": "search", "timestamp": 1.0},
    )
    assert response.status_code == 422
    assert "must be supplied in order" in response.text


def test_an_overdue_request_is_still_pending_until_swept(client):
    """Hiding it would make the queue look empty while a call sat held."""
    _settle_gateway(client)
    client.post(
        "/gateway/evaluate",
        json={"agent_id": "agent-7", "tool": "wire_transfer", "timestamp": 100.0},
    )
    assert len(client.get("/approvals").json()) == 1
    client.post("/approvals/sweep")
    assert client.get("/approvals").json() == []


# ----------------------------------------------------------- auth and tenancy


def test_there_is_no_anonymous_path(anon):
    """A control that answers to whoever asks is worse than no control."""
    for method, path in (
        ("get", "/health"),
        ("get", "/agents"),
        ("get", "/metrics"),
        ("post", "/observe"),
        ("get", "/approvals"),
        ("get", "/keys"),
    ):
        response = (
            anon.post(path, json={}) if method == "post" else anon.get(path)
        )
        assert response.status_code == 401, path


def test_a_bad_token_is_refused(anon):
    anon.headers["Authorization"] = "Bearer attest_deadbeef_nonsense"
    assert anon.get("/health").status_code == 401
    anon.headers["Authorization"] = "Bearer not-even-the-right-shape"
    assert anon.get("/health").status_code == 401


def test_whoami_reports_the_credential(client):
    body = client.get("/whoami").json()
    assert body["role"] == "admin"
    assert body["tenant_id"] == "default"


def test_a_token_is_returned_once_and_never_again(client):
    issued = client.post("/keys", json={"role": "ingest", "label": "gw"}).json()
    assert issued["token"].startswith("attest_")
    assert "shown once" in issued["warning"]

    listed = client.get("/keys").json()
    assert [k["key_id"] for k in listed] == [issued["key_id"]]
    assert all("token" not in k and "token_hash" not in k for k in listed)


def test_an_ingest_credential_cannot_approve_or_configure(client):
    token = client.post("/keys", json={"role": "ingest"}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # It can do its job.
    assert (
        client.post(
            "/gateway/evaluate",
            json={"agent_id": "a", "tool": "search", "timestamp": 1.0},
            headers=headers,
        ).status_code
        == 200
    )
    # And nothing else.
    assert client.get("/agents", headers=headers).status_code == 403
    assert client.get("/approvals", headers=headers).status_code == 403
    assert client.put("/config", json={"theta_low": 0.4}, headers=headers).status_code == 403
    assert client.get("/keys", headers=headers).status_code == 403


def test_an_approver_can_answer_but_not_rewrite_the_thresholds(client):
    """A reviewer who could widen thresholds could stop being asked."""
    token = client.post("/keys", json={"role": "approver"}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/approvals", headers=headers).status_code == 200
    assert client.get("/agents", headers=headers).status_code == 200
    assert client.put("/config", json={"theta_low": 0.4}, headers=headers).status_code == 403
    assert client.post("/keys", json={"role": "admin"}, headers=headers).status_code == 403


def test_a_revoked_key_stops_working(client):
    issued = client.post("/keys", json={"role": "approver"}).json()
    headers = {"Authorization": f"Bearer {issued['token']}"}
    assert client.get("/agents", headers=headers).status_code == 200

    client.delete(f"/keys/{issued['key_id']}")
    assert client.get("/agents", headers=headers).status_code == 401


def test_revoking_an_unknown_key_is_a_404(client):
    assert client.delete("/keys/nope").status_code == 404


def test_tenants_cannot_see_each_other(client, tmp_path, monkeypatch):
    """The property the whole design of TenantContext exists to guarantee."""
    from attest.tenancy import Role

    state = app_module._global_state()
    other = state.keys.issue("other-corp", Role.ADMIN, label="second tenant")
    other_headers = {"Authorization": f"Bearer {other.token}"}

    # Same agent id, different tenants.
    for i in range(40):
        client.post(
            "/observe",
            json={
                "sender": "shared",
                "recipient": "t",
                "intent": "core",
                "action": "q",
                "timestamp": float(i),
                "audit_proof": f"m{i}",
            },
        )

    assert [a["agent_id"] for a in client.get("/agents").json()] == ["shared"]
    assert client.get("/agents", headers=other_headers).json() == []
    assert client.get("/metrics", headers=other_headers).json()["steps"] == 0
    assert client.get("/agents/shared", headers=other_headers).status_code == 404


def test_an_admin_cannot_mint_keys_into_another_tenant(client):
    """The tenant comes from the caller, never from the request body."""
    issued = client.post(
        "/keys", json={"role": "admin", "label": "x", "tenant_id": "victim"}
    ).json()
    assert issued["tenant_id"] == "default"


def test_approvals_are_scoped_to_a_tenant(client):
    from attest.tenancy import Role

    state = app_module._global_state()
    other = state.keys.issue("other-corp", Role.ADMIN)
    other_headers = {"Authorization": f"Bearer {other.token}"}

    _settle_gateway(client)
    held = client.post(
        "/gateway/evaluate",
        json={"agent_id": "agent-7", "tool": "wire_transfer", "timestamp": 100.0},
    ).json()

    assert len(client.get("/approvals").json()) == 1
    assert client.get("/approvals", headers=other_headers).json() == []
    # Nor can the other tenant answer it.
    assert (
        client.post(
            f"/approvals/{held['request_id']}/decide",
            json={"approver": "mallory", "outcome": "approved", "at": 130.0},
            headers=other_headers,
        ).status_code
        == 404
    )


def test_a_query_token_works_only_on_the_sse_path(client):
    """EventSource cannot set headers; that exemption is deliberately narrow.

    Exercised against the dependency rather than over HTTP, because the stream
    never completes and a test client reading it would simply hang.
    """
    from starlette.requests import Request

    state = app_module._global_state()

    def resolve(path: str):
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": path,
                "headers": [],
                "query_string": f"token={BOOTSTRAP}".encode(),
            }
        )
        try:
            return app_module.principal(request, None, state)
        except Exception as exc:
            return exc

    assert resolve("/decisions/stream").role.value == "admin"
    # The same trick must not work anywhere else.
    for path in ("/agents", "/metrics", "/config"):
        assert getattr(resolve(path), "status_code", None) == 401, path


def test_a_query_token_is_ignored_on_ordinary_paths_over_http(anon):
    assert anon.get(f"/agents?token={BOOTSTRAP}").status_code == 401
    assert anon.get(f"/metrics?token={BOOTSTRAP}").status_code == 401


def test_reset_clears_approvals_and_oversight_too(client):
    """Otherwise a reset leaves approvals pointing at agents that no longer exist."""
    _settle_gateway(client)
    client.post(
        "/gateway/evaluate",
        json={"agent_id": "agent-7", "tool": "wire_transfer", "timestamp": 100.0},
    )
    assert client.get("/approvals").json()

    client.post("/reset")

    assert client.get("/approvals").json() == []
    assert client.get("/approvers").json() == []
    assert client.get("/agents").json() == []
