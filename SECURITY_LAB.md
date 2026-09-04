# FlowShield Security Simulation Lab

The security lab provides deterministic, machine-readable demonstrations of five security controls:

- credential stuffing / login rate limiting
- refresh-token replay / token-family and session revocation
- deterministic risky-login outcomes
- approved temporary privileged access and automatic expiry
- PKCE authorization-code replay prevention

## Safety model

The lab is **disabled by default**. A run is accepted only when both controls are satisfied:

1. `SECURITY_LAB_ENABLED=true`
2. `SECURITY_LAB_BASE_URL` exactly matches an origin in `SECURITY_LAB_ALLOWED_BASE_URLS`

Targets are deployment configuration, not request input. URLs containing credentials, paths, query strings, or fragments are rejected. The default allowlist contains only `http://localhost:8000` and `http://127.0.0.1:8000`.

The scenarios are bounded synthetic probes. They invoke production policy and invariant code but do not submit credentials, mint live tokens, modify IAM grants, or send attack traffic. The CLI calls only the allowlisted FlowShield admin API.

For a local backend process:

```text
SECURITY_LAB_ENABLED=true
SECURITY_LAB_BASE_URL=http://localhost:8000
SECURITY_LAB_ALLOWED_BASE_URLS=["http://localhost:8000","http://127.0.0.1:8000"]
```

For execution inside the existing backend Docker container, `localhost:8000` remains the correct origin. If a separate internal CI container calls the Compose service name, explicitly add and select `http://backend:8000`; do not use a wildcard allowlist.

The primary local Compose path makes that explicit by enabling the lab only in its `ENVIRONMENT=local` backend container and selecting only `http://backend:8000`. Application defaults remain disabled. Never copy these Compose values into a shared, staging, or production deployment.

## Admin API

All endpoints require an admin bearer token.

- `GET /admin/security-lab/scenarios` — list the fixed scenario catalogue and enabled state
- `POST /admin/security-lab/scenarios/{scenario_id}/runs` — execute with JSON such as `{"seed": 0}` and persist evidence
- `GET /admin/security-lab/runs` — list persisted runs
- `GET /admin/security-lab/runs/{run_id}` — retrieve one run

Each run records scenario, pass/fail status, seed, target origin, individual checks, and a SHA-256 evidence digest. No credentials or bearer tokens are persisted.

## CLI

Set the token outside shell history where possible:

```text
export FLOW_SHIELD_ADMIN_TOKEN='<admin bearer token>'
export FLOW_SHIELD_BASE_URL='http://localhost:8000'
```

Run from the backend directory or container:

```text
python -m app.security_lab_cli list
python -m app.security_lab_cli run credential-stuffing-rate-limit --seed 0
python -m app.security_lab_cli runs
```

Output is a single JSON document. Exit codes are suitable for CI:

- `0`: request succeeded, and a requested run passed
- `1`: run completed but its evidence failed
- `2`: unsafe configuration, missing token, request error, or API error

## Scope and limitations

The lab verifies deterministic control decisions and workflow state policy, not offensive exploitability. It deliberately does not generate load or execute arbitrary HTTP requests. Existing integration tests separately exercise the rate-limiting middleware, session rotation, risk-policy persistence/login enforcement, PKCE redemption, and Temporal privileged-access workflow.
