# FlowShield AI SDLC

## Safety boundary

FlowShield authorization is deterministic. Model output is advisory, non-enforcing, and non-blocking. A model cannot approve, deny, grant, revoke, call tools, select another agent, or bypass human approval. The privileged-access workflow uses a fixed pair of advisors: `least_privilege` and `security_context`.

Credentials, bearer and refresh tokens, recovery material, raw IP addresses, user-agent strings, names, email addresses, and free-text justifications are prohibited from model prompts and active Temporal workflow payloads. Advisor input is a complete allowlisted schema of bounded categories, booleans, and counts. Unknown or malformed fields fail closed before invocation.

## Versioned artifacts

| Artifact | Current identifier | Change requirement |
| --- | --- | --- |
| Golden risk-policy dataset | `risk-policy-golden.v1.json` | Review expected decisions and dataset card |
| Golden privileged-access advisor dataset | `privileged-access-advisors-golden.v1.json` | Review both fixed advisor roles, expected reasons, and dataset card |
| Advisor output schema | `1` | Add compatibility tests before changing |
| Privileged-access prompt | `privileged-access-v1` | Run privacy, schema, and workflow regression tests |
| Deterministic advisor policy | `privileged-access-policy-v1` | Review reason-code and monotonicity behavior |

Persisted advisory effects include schema, prompt, policy, provider, model, evidence digest, recommendation, reason codes, evidence references, fallback category, and the explicit `enforcing: false` marker. They do not persist prompt text or raw evidence.

## Merge gates

The pull-request gate runs:

- deterministic golden-case, monotonicity, and fail-closed policy evaluations;
- prompt privacy canaries;
- strict model-output and bounded-evidence tests;
- non-enforcement and model-outage workflow tests;
- session-aware authorization, BFF, CSRF, and token non-disclosure tests;
- critical backend-module and repository-wide frontend coverage floors;
- Python and npm advisory audits;
- repository secret/artifact policy checks;
- filesystem, configuration, secret, and final-container-image scans;
- Compose validation and production builds.

Synthetic evaluation data is documented in [backend/evals/dataset-card.md](backend/evals/dataset-card.md). It is a regression suite, not evidence of production accuracy, fairness, or fitness for autonomous decision-making.

Run the blocking, model-free evaluation gate locally from `backend/` with:

	pytest -q tests/evals

CI invokes both evaluation modules explicitly in the backend-focused job. The gate requires exact deterministic outputs, complete allowlisted evidence, rejection of privacy canaries and malformed model output, deterministic fallback for disabled/invalid/unavailable advisors, and an immutable non-enforcing marker. It performs no external model calls and incurs no model spend.

## Release policy

A release is blocked when deterministic expected outcomes change unexpectedly, a fail-closed invariant fails, sensitive canaries enter advisor evidence or a prompt, model output bypasses schema validation, deterministic fallback changes unexpectedly, an advisor can affect enforcement, critical coverage falls below its baseline, or a configured high/critical dependency or image scan fails.

Optional Ollama evaluation is manual or scheduled and must use synthetic, privacy-reviewed inputs. External model availability is never a pull-request dependency. Model changes require recording the model identifier and comparing recommendation distribution, disagreement, invalid-output rate, and fallback rate before promotion.

## Operations and rollback

Metrics use bounded labels only: advisor role, provider, status, prompt version, and schema version. Prompts, evidence, user IDs, request IDs, and free text are never metric labels. Operators monitor advisor latency, availability, invalid-output fallback, recommendation distribution, and disagreement with deterministic policy.

Rollback is immediate: disable `PRIVILEGED_ACCESS_AGENT_AI_ENABLED` and `RISK_POLICY_AI_SHADOW_ENABLED`. Deterministic policy and human approval continue to operate. Advisor outages and invalid output fall back to deterministic, non-enforcing reviews and cannot block a human-approved workflow.

## Governance

- Any expansion of model evidence requires privacy and threat review.
- Any new advisor role requires a fixed purpose, bounded input/output contract, and explicit non-enforcement tests.
- Production data must not be added to evaluation fixtures without provenance, consent, retention, and de-identification review.
- AI-generated explanations must not be treated as security evidence or authoritative decisions.
- Dataset, prompt, schema, policy, and model changes are reviewed as code and retained in version control.
