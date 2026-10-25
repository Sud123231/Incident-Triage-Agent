import hashlib
import json
import app as agent
import pytest
from fastapi.testclient import TestClient
from store import Store


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "store", Store(str(tmp_path / "test.sqlite3")))
    async def planner(payload):
        return ({
            "rootCause": "db_pool_exhausted",
            "evidence": ["ev_001", "ev_002"],
            "diagnostics": [
                {"toolName": "query_metrics", "arguments": {"service": "billing"}},
                {"toolName": "query_logs", "arguments": {"service": "billing"}},
            ],
            "effect": {"toolName": "rollback_deployment", "arguments": {"service": "billing", "deployment_id": "deploy-7"}},
        }, "test-model")
    monkeypatch.setattr(agent, "call_planner", planner)
    return TestClient(agent.app)


CATALOG = [
    {"name": "query_metrics", "description": "metrics", "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}},
    {"name": "query_logs", "description": "logs", "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}}},
    {"name": "rollback_deployment", "description": "rollback", "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}, "deployment_id": {"type": "string"}}}},
]


def incident(run_id="run-12345678"):
    return {
        "profile": "ga5-incident-agent/v2", "runId": run_id, "agentName": "incident-response",
        "publicMarker": "marker-safe", "sensitive": {"accessToken": "DO_NOT_EXPORT_TOKEN", "privateNote": "DO_NOT_EXPORT_NOTE"},
        "incident": {"incidentId": "inc-1", "title": "Database pool exhaustion", "service": "billing", "deployment_id": "deploy-7", "severity": "SEV-1",
                     "transcript": "[ev_001] pool utilization reached maximum\n[ev_002] connection acquisition failures",
                     "allowedRootCauses": ["db_pool_exhausted"]},
        "toolCatalog": CATALOG,
        "policy": {"maximumDiagnostics": 3, "effectTools": ["rollback_deployment"],
                   "approvalRequiredFor": ["rollback_deployment"], "doNotExport": ["sensitive"]},
    }


def post_receipt(client, run_id, body):
    return client.post(f"/v2/incidents/{run_id}/receipts", json=body)


def test_validation_and_not_found(client):
    assert client.get("/health").status_code == 200
    assert client.post("/v2/incidents", json={"profile": "unsupported"}).status_code == 422
    assert client.get("/v2/incidents/no-such-run").status_code == 404
    assert client.post("/v2/incidents", content="not json", headers={"content-type": "application/json"}).status_code == 400


def test_create_replay_get_conflict_and_redaction(client):
    p = incident()
    first = client.post("/v2/incidents", json=p)
    assert first.status_code == 200
    state = first.json()
    assert state["status"] == "waiting"
    assert 1 <= len(state["dispatches"]) <= 3
    assert len(state["diagnosis"]["evidence"]) in (2, 3, 4)
    assert len(set(state["diagnosis"]["evidence"])) == len(state["diagnosis"]["evidence"])
    for dispatch in state["dispatches"]:
        assert set(dispatch["evidence"]).issubset(set(state["diagnosis"]["evidence"]))
        assert len(dispatch["actionId"]) >= 8 and len(dispatch["callId"]) >= 8
    assert client.post("/v2/incidents", json=p).text == first.text
    assert client.get("/v2/incidents/" + state["runId"]).text == first.text
    assert "DO_NOT_EXPORT_TOKEN" not in first.text and "DO_NOT_EXPORT_NOTE" not in first.text
    changed = incident(); changed["incident"]["title"] = "changed content"
    assert client.post("/v2/incidents", json=changed).status_code == 409


def test_timeout_suppresses_effect(client):
    p = incident("run-timeout-1234")
    state = client.post("/v2/incidents", json=p).json()
    a, b = state["dispatches"]
    result = post_receipt(client, state["runId"], {"receiptId": "receipt-timeout-01", "outcomes": [
        {"actionId": a["actionId"], "callId": a["callId"], "attempt": 1, "status": 0, "errorType": "timeout", "resultClass": "timeout", "nonce": "n-timeout-0001"},
        {"actionId": b["actionId"], "callId": b["callId"], "attempt": 1, "status": 200, "resultClass": "ok", "nonce": "n-success-0001"},
    ]})
    assert result.status_code == 200
    final = result.json()
    assert final["status"] == "failed"
    assert not any(x["phase"] == "effect" for x in final["actionLog"])
    assert not final.get("dispatches")


def test_503_retry_then_approval_then_effect_completion(client):
    state = client.post("/v2/incidents", json=incident("run-approval-1234")).json()
    first, second = state["dispatches"]
    retry_response = post_receipt(client, state["runId"], {"receiptId": "receipt-503-0001", "outcomes": [
        {"actionId": first["actionId"], "callId": first["callId"], "attempt": 1, "status": 503, "resultClass": "retry", "nonce": "n-503-0001"}
    ]})
    assert retry_response.status_code == 200
    assert retry_response.json().get("approvals", []) == []
    pending = retry_response.json()["dispatches"]
    assert sorted((d["toolName"], d["attempt"]) for d in pending) == [("query_logs", 1), ("query_metrics", 2)]
    retry = next(d for d in pending if d["attempt"] == 2)
    other = next(d for d in pending if d["callId"] != retry["callId"])
    diagnostics = post_receipt(client, state["runId"], {"receiptId": "receipt-diagnostics-02", "outcomes": [
        {"actionId": retry["actionId"], "callId": retry["callId"], "attempt": 2, "status": 200, "resultClass": "ok", "nonce": "n-retry-ok-01"},
        {"actionId": other["actionId"], "callId": other["callId"], "attempt": 1, "status": 200, "resultClass": "ok", "nonce": "n-other-ok-01"},
    ]})
    waiting = diagnostics.json()
    assert diagnostics.status_code == 200 and waiting["status"] == "waiting"
    assert waiting["dispatches"] == [] and len(waiting["approvals"]) == 1
    approval = waiting["approvals"][0]
    expected = hashlib.sha256(json.dumps({"service": "billing", "deployment_id": "deploy-7"}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    assert approval["argumentsDigest"] == expected
    approved = post_receipt(client, state["runId"], {"receiptId": "receipt-approval-03", "approvals": [
        {"approvalId": approval["approvalId"], "decision": "approved", "nonce": "n-approved-0001"}
    ]}).json()
    assert len(approved["dispatches"]) == 1
    effect = approved["dispatches"][0]
    assert effect["phase"] == "effect" and effect["actionId"] == approval["actionId"]
    assert effect["approvalId"] == approval["approvalId"] and effect["approvalNonce"] == "n-approved-0001"
    done_body = {"receiptId": "receipt-effect-04", "outcomes": [
        {"actionId": effect["actionId"], "callId": effect["callId"], "attempt": 1, "status": 200, "resultClass": "done", "nonce": "n-effect-done-01"}
    ]}
    done = post_receipt(client, state["runId"], done_body)
    assert done.status_code == 200 and done.json()["status"] == "completed"
    assert not done.json().get("dispatches") and not done.json().get("approvals")
    assert post_receipt(client, state["runId"], done_body).text == done.text
    final_spans = done.json()["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    metric_client_spans = [sp for sp in final_spans if sp["name"] == "POST tool/query_metrics"]
    assert len(metric_client_spans) == 2
    metric_by_attempt = {next(a["value"].get("intValue") for a in sp["attributes"] if a["key"] == "ga5.attempt"): sp for sp in metric_client_spans}
    first_attrs = {a["key"]: a["value"] for a in metric_by_attempt[1]["attributes"]}
    retry_attrs = {a["key"]: a["value"] for a in metric_by_attempt[2]["attributes"]}
    assert first_attrs["error.type"]["stringValue"] == "503"
    assert first_attrs["http.request.resend_count"]["intValue"] == 0
    assert metric_by_attempt[1]["status"]["code"] == 2
    assert retry_attrs["http.request.resend_count"]["intValue"] == 1
    join = next(sp for sp in final_spans if sp["name"] == "incident.join")
    assert len(join["links"]) == 2
    changed = {"receiptId": "receipt-effect-04", "outcomes": []}
    assert post_receipt(client, state["runId"], changed).status_code == 409


def test_otlp_correlation_and_redaction(client):
    state = client.post("/v2/incidents", json=incident("run-trace-1234")).json()
    spans = state["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    trace_id = spans[0]["traceId"]
    assert all(s["traceId"] == trace_id for s in spans)
    assert sum(s["name"] == "POST /v2/incidents" for s in spans) == 1
    assert sum(s["name"] == "invoke_agent incident-response" for s in spans) == 1
    assert sum(s["name"] == "chat incident-plan" for s in spans) == 1
    assert sum(s["name"] == "incident.join" for s in spans) == 1
    for s in spans:
        attrs = {x["key"]: x["value"] for x in s["attributes"]}
        assert "ga5.run.id" in attrs and "ga5.public.marker" in attrs
    for dispatch in state["dispatches"]:
        span_id = dispatch["traceparent"].split("-")[2]
        assert any(s["kind"] == 3 and s["spanId"] == span_id for s in spans)
    exported = json.dumps(state["otlp"])
    assert "DO_NOT_EXPORT_TOKEN" not in exported and "DO_NOT_EXPORT_NOTE" not in exported
    assert "gen_ai.tool.call.arguments" not in exported and "gen_ai.tool.call.result" not in exported



def test_effect_503_is_retried_once(client):
    state = client.post("/v2/incidents", json=incident("run-effect-retry-1234")).json()
    first, second = state["dispatches"]
    result = post_receipt(client, state["runId"], {"receiptId": "receipt-diag-success-01", "outcomes": [
        {"actionId": first["actionId"], "callId": first["callId"], "attempt": 1, "status": 200, "resultClass": "ok", "nonce": "n-diag-1"},
        {"actionId": second["actionId"], "callId": second["callId"], "attempt": 1, "status": 200, "resultClass": "ok", "nonce": "n-diag-2"},
    ]})
    approval = result.json()["approvals"][0]
    result = post_receipt(client, state["runId"], {"receiptId": "receipt-effect-approval-02", "approvals": [
        {"approvalId": approval["approvalId"], "decision": "approved", "nonce": "n-approval"}
    ]})
    effect = result.json()["dispatches"][0]
    retried = post_receipt(client, state["runId"], {"receiptId": "receipt-effect-503-03", "outcomes": [
        {"actionId": effect["actionId"], "callId": effect["callId"], "attempt": 1, "status": 503, "resultClass": "retry", "nonce": "n-effect-503"}
    ]})
    retry = retried.json()["dispatches"]
    assert len(retry) == 1 and retry[0]["phase"] == "effect" and retry[0]["attempt"] == 2
    assert retry[0]["actionId"] == effect["actionId"] and retry[0]["callId"] == effect["callId"]
    assert retry[0]["approvalId"] == effect["approvalId"] and retry[0]["approvalNonce"] == effect["approvalNonce"]
    finished = post_receipt(client, state["runId"], {"receiptId": "receipt-effect-success-04", "outcomes": [
        {"actionId": retry[0]["actionId"], "callId": retry[0]["callId"], "attempt": 2, "status": 200, "resultClass": "ok", "nonce": "n-effect-ok"}
    ]})
    assert finished.status_code == 200 and finished.json()["status"] == "completed"

def test_incoming_trace_context_and_tracestate(client):
    p = incident("run-traceparent-1234")
    p["traceparent"] = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
    p["tracestate"] = "vendor=value"
    response = client.post("/v2/incidents", json=p)
    assert response.status_code == 200
    state = response.json()
    spans = state["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert all(span["traceId"] == "0123456789abcdef0123456789abcdef" for span in spans)
    server = next(span for span in spans if span["name"] == "POST /v2/incidents")
    assert server["parentSpanId"] == "0123456789abcdef"
    assert all(dispatch.get("tracestate") == "vendor=value" for dispatch in state["dispatches"])


def test_create_replay_after_state_progression_returns_original_response(client):
    payload = incident("run-replay-progress-1234")
    original = client.post("/v2/incidents", json=payload)
    assert original.status_code == 200
    original_text = original.text
    initial = original.json()
    receipt_body = {
        "receiptId": "receipt-replay-progress-01",
        "outcomes": [
            {"actionId": item["actionId"], "callId": item["callId"], "attempt": 1,
             "status": 200, "resultClass": "ok", "nonce": "nonce-replay-" + str(i)}
            for i, item in enumerate(initial["dispatches"])
        ],
    }
    progressed = post_receipt(client, initial["runId"], receipt_body)
    assert progressed.status_code == 200
    assert progressed.json()["approvals"]

    # Replaying the original create request returns the original snapshot, not progressed state.
    replayed_create = client.post("/v2/incidents", json=payload)
    assert replayed_create.status_code == 200
    assert replayed_create.text == original_text

    approval = progressed.json()["approvals"][0]
    approved = post_receipt(client, initial["runId"], {
        "receiptId": "receipt-replay-progress-02",
        "approvals": [{"approvalId": approval["approvalId"], "decision": "approved", "nonce": "nonce-approval-replay"}],
    })
    assert approved.status_code == 200

    # Replaying an earlier receipt after later state changes returns its original response.
    receipt_replay = post_receipt(client, initial["runId"], receipt_body)
    assert receipt_replay.status_code == 200
    assert receipt_replay.text == progressed.text


def test_approval_denial_suppresses_destructive_effect(client):
    state = client.post("/v2/incidents", json=incident("run-denial-1234")).json()
    outcomes = [{"actionId": d["actionId"], "callId": d["callId"], "attempt": 1,
                 "status": 200, "resultClass": "ok", "nonce": "nonce-denial-" + str(i)}
                for i, d in enumerate(state["dispatches"])]
    waiting = post_receipt(client, state["runId"], {
        "receiptId": "receipt-denial-diagnostics", "outcomes": outcomes,
    }).json()
    approval = waiting["approvals"][0]
    denied = post_receipt(client, state["runId"], {
        "receiptId": "receipt-denial-decision",
        "approvals": [{"approvalId": approval["approvalId"], "decision": "denied", "nonce": "nonce-denied"}],
    })
    assert denied.status_code == 200
    final = denied.json()
    assert final["status"] == "failed"
    assert not final.get("dispatches")
    assert not any(action["phase"] == "effect" for action in final["actionLog"])
    assert "effect_suppressed_approval_denied" in final["suppressed"]


def test_tool_arguments_validate_schema_and_incident_target():
    schema = {
        "type": "object",
        "properties": {"service": {"type": "string"}, "deployment_id": {"type": "string"}},
        "required": ["service", "deployment_id"],
        "additionalProperties": False,
    }
    incident_context = {"service": "billing", "deployment_id": "deploy-7"}
    assert agent.safe_arguments(schema, {"service": "billing", "deployment_id": "deploy-7"}, incident_context) == {
        "service": "billing", "deployment_id": "deploy-7"
    }
    with pytest.raises(ValueError):
        agent.safe_arguments(schema, {"service": "billing"}, incident_context)
    with pytest.raises(ValueError):
        agent.safe_arguments(schema, {"service": "attacker", "deployment_id": "deploy-7"}, incident_context)
    with pytest.raises(ValueError):
        agent.safe_arguments(schema, {"service": "billing", "deployment_id": "deploy-7", "extra": True}, incident_context)


def test_invalid_destructive_target_suppresses_effect(client, monkeypatch):
    async def bad_target_planner(payload):
        return ({
            "rootCause": "db_pool_exhausted",
            "evidence": ["ev_001", "ev_002"],
            "diagnostics": [
                {"toolName": "query_metrics", "arguments": {"service": "billing"}},
                {"toolName": "query_logs", "arguments": {"service": "billing"}},
            ],
            "effect": {"toolName": "rollback_deployment", "arguments": {"service": "attacker", "deployment_id": "deploy-7"}},
        }, "test-model")
    monkeypatch.setattr(agent, "call_planner", bad_target_planner)
    state = client.post("/v2/incidents", json=incident("run-wrong-target-1234")).json()
    outcomes = [{"actionId": d["actionId"], "callId": d["callId"], "attempt": 1,
                 "status": 200, "resultClass": "ok", "nonce": "nonce-target-" + str(i)}
                for i, d in enumerate(state["dispatches"])]
    final = post_receipt(client, state["runId"], {
        "receiptId": "receipt-target-diagnostics", "outcomes": outcomes,
    }).json()
    assert final["status"] == "failed"
    assert not final.get("dispatches")
    assert not any(action["phase"] == "effect" for action in final["actionLog"])
    assert "effect_suppressed_invalid_arguments" in final["suppressed"]


def test_multiple_diagnostic_503s_each_get_one_retry(client):
    state = client.post("/v2/incidents", json=incident("run-multi-503-1234")).json()
    first, second = state["dispatches"]
    response = post_receipt(client, state["runId"], {
        "receiptId": "receipt-multi-503-01",
        "outcomes": [
            {"actionId": first["actionId"], "callId": first["callId"], "attempt": 1,
             "status": 503, "resultClass": "retry", "nonce": "nonce-multi-503-a"},
            {"actionId": second["actionId"], "callId": second["callId"], "attempt": 1,
             "status": 503, "resultClass": "retry", "nonce": "nonce-multi-503-b"},
        ],
    })
    assert response.status_code == 200
    result = response.json()
    assert not result.get("approvals")
    assert len(result["dispatches"]) == 2
    assert all(item["attempt"] == 2 for item in result["dispatches"])
    assert {item["callId"] for item in result["dispatches"]} == {first["callId"], second["callId"]}


def test_destructive_tools_require_approval_even_if_policy_omits_them(client):
    payload = incident("run-unconditional-approval-1234")
    payload["policy"]["approvalRequiredFor"] = []
    state = client.post("/v2/incidents", json=payload).json()
    outcomes = [
        {"actionId": d["actionId"], "callId": d["callId"], "attempt": 1,
         "status": 200, "resultClass": "ok", "nonce": "nonce-unconditional-" + str(i)}
        for i, d in enumerate(state["dispatches"])
    ]
    result = post_receipt(client, state["runId"], {
        "receiptId": "receipt-unconditional-diags", "outcomes": outcomes,
    }).json()
    assert result["status"] == "waiting"
    assert result["dispatches"] == []
    assert len(result["approvals"]) == 1
    assert result["approvals"][0]["toolName"] == "rollback_deployment"


def test_invalid_traceparent_drops_tracestate(client):
    payload = incident("run-invalid-traceparent-1234")
    payload["traceparent"] = "not-a-valid-traceparent"
    payload["tracestate"] = "vendor=value"
    response = client.post("/v2/incidents", json=payload)
    assert response.status_code == 200
    state = response.json()
    assert state["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"] != "not-a-valid-traceparent"
    assert all("tracestate" not in dispatch for dispatch in state["dispatches"])


def test_actual_planner_http_protocol_with_mocked_provider(monkeypatch):
    import asyncio
    import httpx
    import json as json_module

    monkeypatch.setenv("AI_BASE_URL", "https://mock-provider.invalid/v1")
    monkeypatch.setenv("AI_API_KEY", "test-api-key")
    monkeypatch.setenv("AI_MODEL", "test-model")
    captured = {}
    plan = {
        "rootCause": "db_pool_exhausted",
        "evidence": ["ev_001", "ev_002"],
        "diagnostics": [{"toolName": "query_metrics", "arguments": {"service": "billing"}}],
        "effect": {"toolName": "rollback_deployment", "arguments": {"service": "billing", "deployment_id": "deploy-7"}},
    }

    def handler(request):
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json_module.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"choices": [{"message": {"content": json_module.dumps(plan)}}]})

    real_async_client = httpx.AsyncClient
    def mocked_async_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)
    monkeypatch.setattr(agent.httpx, "AsyncClient", mocked_async_client)

    payload = incident("run-real-planner-protocol-1234")
    result, model = asyncio.run(agent.call_planner(payload))
    assert result == plan
    assert model == "test-model"
    assert captured["url"] == "https://mock-provider.invalid/v1/chat/completions"
    sent_text = json_module.dumps(captured["body"])
    assert "DO_NOT_EXPORT_TOKEN" not in sent_text
    assert "DO_NOT_EXPORT_NOTE" not in sent_text
    assert "test-api-key" not in sent_text
    assert captured["body"]["model"] == "test-model"


def test_destructive_resource_id_must_be_grounded():
    schema = {
        "type": "object",
        "properties": {"service": {"type": "string"}, "deployment_id": {"type": "string"}},
        "required": ["service", "deployment_id"],
        "additionalProperties": False,
    }
    incident_context = {"service": "billing", "transcript": "[ev_1] billing service has connection failures"}
    with pytest.raises(ValueError):
        agent.safe_arguments(
            schema,
            {"service": "billing", "deployment_id": "unmentioned-deployment"},
            incident_context,
            destructive=True,
        )
