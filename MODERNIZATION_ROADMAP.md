# FlowShield Modernization Roadmap

Last reviewed: 4 September 2026

## Objective

Modernize the project incrementally while keeping it runnable. Security and correctness gaps take priority over speculative AI features. Every slice must include tests, observable behavior, and a rollback path.

## Current State

| Area | State | Evidence-based summary |
| --- | --- | --- |
| Core authentication | Partial | Registration, login, refresh, reset, verification, and resend endpoints exist. Recovery tokens are hashed at rest, expire, are atomically consumed once, and are delivered through SMTP or an isolated development mail sink. |
| OAuth2 and PKCE | Implemented | The active authorization-code path requires PKCE S256, exact registered redirects, hashed grants, atomic one-time redemption, client-type-aware authentication, and non-cacheable token responses. Legacy non-PKCE endpoints return HTTP 410. |
| IAM | Partial | Models, APIs, activities, and workflow skeletons exist. Scope enforcement, conditional permissions, approvals, and complete audit integration remain incomplete. |
| Rate limiting | Partial | APIs, activities, workflows, and tests exist. Login and registration integration needs verification and completion. |
| Behavioral analytics | Partial | Activities, workflows, APIs, and dashboard components exist. Core login integration and production-quality model evaluation are incomplete. |
| MFA | Partial | Workflow and activities exist, but a complete API, enrollment flow, recovery codes, and policy enforcement are missing. |
| Predictive attack simulation | Experimental | API, workflow, activities, schema, tests, and UI exist. Isolation, authorization, safety controls, and model-quality claims require validation before production use. |
| AI inference | Experimental | Ollama integration and rule-based fallbacks exist. Accuracy claims are not backed by versioned datasets, trained artifacts, or repeatable evaluations. |
| Frontend | Modernization started | User and admin interfaces exist. Icons now use Lucide React; the current Create React App toolchain still needs migration. |
| Delivery | Missing | No CI workflow, dependency update automation, SBOM, signing, or security gates are present. |

## Delivery Principles

1. Do not implement every roadmap idea at once.
2. Complete thin end-to-end slices before adding more models or dashboards.
3. Keep AI advisory until deterministic policy checks and human-review paths are established.
4. Do not claim model accuracy without a versioned evaluation dataset and reproducible results.
5. Pin runtimes, containers, application dependencies, prompts, and model identifiers.
6. Preserve a non-AI fallback for authentication-critical decisions.

## Phased Plan

### Phase 1: Secure the existing authentication path

- Enforce email verification consistently. Started in this modernization pass.
- Enforce PKCE S256 across authorization-code creation and token exchange. Complete.
- Add login and password-reset rate limiting.
- Add refresh-token rotation, reuse detection, and revocation tests.
- Remove sensitive tokens and verification links from production logs. Complete.
- Add integration tests for register, verify, login, refresh, logout, and reset.

Done when the complete authentication journey passes without Temporal, with Temporal, and with invalid or replayed credentials.

### Phase 2: Complete IAM and auditability

- Apply permission checks to every IAM management endpoint.
- Enforce scope hierarchy in service queries rather than only in the UI.
- Persist immutable audit events for authentication and IAM changes.
- Complete role-assignment approval and access-review workflows.
- Add an IAM management frontend for roles, permissions, scopes, and reviews.

Done when unauthorized users cannot mutate IAM state and every privileged change has an attributable audit event.

### Phase 3: Add modern authentication methods

- Add passkeys with WebAuthn as the preferred phishing-resistant authentication method.
- Add TOTP enrollment and recovery codes as a compatibility option.
- Introduce step-up authentication based on explicit policy and explainable risk signals.
- Add session and device management with user-visible revocation.

Done when a user can enroll, authenticate, recover, and revoke credentials without administrator intervention.

### Phase 4: Make AI measurable and safe

- Replace broad model claims with a versioned risk-scoring contract.
- Build a labeled, privacy-reviewed evaluation dataset and dataset card.
- Add offline evaluation for precision, recall, false-positive rate, calibration, latency, and subgroup behavior.
- Add prompt and model versioning for local inference.
- Use structured model outputs validated by schemas.
- Add shadow mode before AI can influence step-up or deny decisions.
- Monitor drift and preserve deterministic fallbacks.

Current ecosystem direction to evaluate includes small local models, structured outputs, tool-constrained agents, retrieval only where provenance is required, and OpenTelemetry-based AI observability. Libraries and model versions must be selected only after compatibility and evaluation testing.

### Phase 5: Platform and dependency modernization

- Migrate the frontend from Create React App to Vite before a React major upgrade.
- Keep Node on an actively supported LTS line; the frontend container now targets Node 24.
- Introduce a Python project manifest and reproducible lockfile, preferably with `uv` after compatibility testing.
- Upgrade FastAPI, Pydantic, Temporal, SQLAlchemy, and test tooling in separate, tested changes.
- Pin all container images by immutable version or digest.
- Separate heavyweight ML dependencies from the core authentication runtime.

Done when clean installs and container builds are reproducible and all supported runtimes are within their security-support windows.

### Phase 6: Delivery and operations

- Add CI for frontend tests/build and backend unit/integration tests.
- Add dependency, secret, SAST, and container scanning without suppressing findings.
- Generate an SBOM and sign release artifacts.
- Add OpenTelemetry traces, metrics, and structured logs across API and Temporal boundaries.
- Define SLOs for login availability, latency, workflow completion, and false-positive rate.

## Immediate Backlog

1. Add rate limiting to login, registration, and password reset.
2. Remove verification and reset tokens from logs; introduce an explicit development-only mail sink.
3. Add IAM authorization decorators and audit events to mutation endpoints.
4. Implement passkey enrollment and authentication as the next user-facing vertical slice.
5. Add a Vite migration branch with parity tests.
6. Establish AI evaluation before enabling any model-driven blocking behavior.

## Rollback Strategy

Each phase should be delivered as small reversible changes. New authentication methods and risk decisions must be guarded by configuration flags. Existing deterministic authentication remains authoritative until new paths satisfy their acceptance tests and operational targets.
