# Public HTTPS Incident Agent

FastAPI implementation of the `ga5-incident-agent/v2` contract. It stores runs and receipts in SQLite, makes one model-planning call for each first-seen run, and does not call the model on GET, receipt processing, or replay.

## Run locally
1. Use Python 3.11+.
2. `python -m venv .venv`
3. Windows: `.venv\\Scripts\\activate`; macOS/Linux: `source .venv/bin/activate`
4. `pip install -r requirements.txt`
5. Copy `.env.example` to `.env` and set `AI_BASE_URL`, `AI_API_KEY`, and `AI_MODEL`. The app loads `.env` at startup. Never commit or share `.env`; use your hosting dashboard for deployed secrets.
6. `uvicorn app:app --host 0.0.0.0 --port 8000`

Deploy to a public HTTPS host (Render is configured by `render.yaml`). Set the three AI environment variables in the host dashboard. Submit the HTTPS origin only, without a path, query, fragment, or credentials.

## Routes
- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`
- `GET /health`

## Important implementation notes
- Never send `sensitive` to the model. Transcript and catalog are supplied as task data; quoted transcript content is explicitly framed as untrusted evidence.
- SQLite is durable across process restarts when the host has persistent disk storage. Configure a persistent disk or use a managed database for production.
- The agent does not execute real infrastructure tools. It emits dispatches for the grader to execute and consumes authoritative receipts.
- All emitted OTLP spans are built from stored dispatch/receipt state and omit transcript, prompts, arguments, results, and credentials.
- Run the requirement-level regression tests with `pip install -r requirements-dev.txt` followed by `pytest -v`. These use a mocked model planner and do not consume API credits. The suite includes replay after state progression, approval denial, schema validation, destructive-target suppression, simultaneous 503 retries, unconditional destructive-action approval, trace-context fallback, and a mocked AI-provider protocol test. An optional `test_real_model_integration.py` validates actual model output when real `AI_BASE_URL`, `AI_API_KEY`, and `AI_MODEL` values are configured; it is skipped by default to avoid API charges. Run the HTTP smoke tests against a running server with `python test_agent.py http://127.0.0.1:8000`.

## Environment setup

The application expects these names consistently in `.env` and the hosting dashboard:
- `AI_BASE_URL`
- `AI_API_KEY`
- `AI_MODEL`
- `AI_TIMEOUT_SECONDS` (optional)
- `DATABASE_PATH` (optional)

The example file uses placeholders. Replace them locally; never put real credentials into source control or the project ZIP.

## Replay and argument safety

- The initial create response is stored and replayed for an identical `runId` request, even after the run has progressed.
- Each accepted receipt stores the exact response associated with that receipt ID; replaying that receipt returns its stored response. Reusing a receipt ID with changed content returns HTTP 409.
- Tool arguments are validated against the supplied JSON Schema. Where the incident has an explicit structured target (for example `service` or `deployment_id`), mismatched targets are rejected. Destructive tools listed by policy are dispatched only after approval.
