# FlowShield one-command local demo

## Start

Prerequisite: Docker with Compose v2.20 or later and at least 6 GB of free memory.

```text
make demo
```

Equivalent: `./scripts/demo.sh`. To add the optional Ollama container and enable the non-enforcing AI risk-policy shadow, use `make demo-ai` or `./scripts/demo.sh --ai`. No model is pulled automatically; choose and pull a model explicitly after startup.

The documented ports are defaults. If port 8000 is already occupied, for example, start with `BACKEND_PORT=18000 OIDC_ISSUER=http://localhost:18000 make demo`; keep the issuer aligned with the externally published API port.

The command builds the API and Vite frontend, waits for health checks, creates/reconciles the schema, seeds deterministic demo data, and starts the complete local platform. Re-running it is safe. Use `make down` to stop it. `make reset` deletes local PostgreSQL, Redis, OIDC key, Prometheus, Grafana, and Ollama volumes.

## URLs

| Capability | URL | Authentication |
| --- | --- | --- |
| FlowShield frontend | http://localhost:3000 | Demo persona below |
| FastAPI / OpenAPI | http://localhost:8000/docs | Endpoint-dependent |
| Liveness / readiness | http://localhost:8000/health and http://localhost:8000/health/ready | None |
| Prometheus metrics | http://localhost:8000/metrics | Localhost only |
| OIDC discovery / JWKS | http://localhost:8000/.well-known/openid-configuration and http://localhost:8000/oauth2/jwks | None |
| Temporal UI | http://localhost:8081 | Local-only, no auth |
| Mailpit inbox | http://localhost:8025 | Local-only, no auth |
| Prometheus | http://localhost:9090 | Local-only, no auth |
| Grafana | http://localhost:3001 | `admin` / `flowshield-local-only` |
| Ollama (`ai` profile) | http://localhost:11434 | Local-only, no auth |

All published ports bind to loopback. Do not expose this stack to a shared or public network.

## Demo personas

| Persona | Email | Legacy role | IAM role | IAM scopes |
| --- | --- | --- | --- | --- |
| Super administrator | `super.admin@temporal-auth.com` | `admin` + superuser | `super_admin` | ACME Corp |
| Administrator | `admin@temporal-auth.com` | `admin` | `admin` | ACME Corp |
| Team manager | `manager@temporal-auth.com` | `moderator` | `manager` | ACME Corp, Engineering |
| Moderator | `moderator@temporal-auth.com` | `moderator` | `moderator` | Engineering |
| Analyst | `analyst@temporal-auth.com` | `user` | `analyst` | Marketing |
| User | `user@temporal-auth.com` | `user` | `user` | Frontend Team |
| Unverified guest | `guest@temporal-auth.com` | `user` | `guest` | None |

Passwords are generated cryptographically on first bootstrap and persisted only in the `demo_credentials` Docker volume. Run `make demo-credentials` to display them explicitly. Never copy the output into source control, CI logs, screenshots, or shared terminals.

### OAuth 2.1 / OIDC client

- Client ID: `flowshield-local`
- Client type: public (no client secret)
- Grant types: authorization code with PKCE, refresh token
- Redirect URI: `http://localhost:3000/callback`
- Scopes: `openid profile email read write`
- ID-token signing: generated RSA-2048 key stored only in the Docker volume `oidc_keys`; the private key is never committed or mounted into the frontend.

## What starts

PostgreSQL, Redis, Temporal, Temporal UI, the backend API, a general Temporal worker on `oauth2-task-queue`, a dedicated identity worker on `flowshield-identity-ops-v1`, the Vite-built frontend served by unprivileged nginx, Mailpit, OpenTelemetry Collector, Prometheus, and Grafana. The optional `ai` profile adds Ollama.

The backend exports RED metrics at `/metrics` and traces over OTLP to the collector. Prometheus scrapes both the API and collector; Grafana provisions a Prometheus datasource and the **FlowShield API Overview** dashboard. Collector trace output is intentionally kept in local collector logs to avoid adding another datastore to the default stack.

## Security lab: local only

The Compose path explicitly enables the bounded deterministic security lab and allowlists only the internal `http://backend:8000` origin. It cannot accept caller-selected targets. The feature remains disabled in application defaults and must not be copied into production configuration. See `SECURITY_LAB.md` for its API and safety model.

## Operational checks

```text
docker compose ps
curl --fail http://localhost:8000/health/ready
curl --fail http://localhost:8000/oauth2/jwks
curl --fail http://localhost:8000/metrics
```

Use `docker compose logs -f backend worker identity-worker otel-collector` for API, workflow, and trace diagnostics.

## Limitations and off-ramp

- This is a laptop demo, not a production topology: TLS and infrastructure UI authentication are not configured, data is single-node, and volumes are not backed up.
- The collector logs traces but the thin default stack does not include a trace query UI. Add Tempo or Jaeger when trace retention/search is needed.
- Database creation uses SQLAlchemy plus the existing idempotent SQL migration. A production deployment should move fully to reviewed Alembic revisions.
- Ollama starts without downloading a model because models are large and hardware-dependent.
- The focused security and identity suite is the CI merge gate. Historical compatibility tests and the optional heavyweight ML profile are not part of the default local runtime.
- Images use pinned version tags rather than immutable digests. Production release automation should resolve, sign, and verify image digests.
- Override local defaults through environment variables only for local experimentation; use a secrets manager and asymmetric access tokens in production.
