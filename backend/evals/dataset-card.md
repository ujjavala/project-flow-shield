# FlowShield AI Evaluation Dataset Card

## Purpose

These versioned synthetic cases verify deterministic authentication-risk and privileged-access advisory behavior. They are release tests, not claims of real-world model accuracy.

The suite contains:

- `risk-policy-golden.v1.json` for authoritative authentication-risk outcomes; and
- `privileged-access-advisors-golden.v1.json` for the fixed `least_privilege` and `security_context` advisor roles.

## Provenance and composition

- Authored from documented policy boundaries and security invariants.
- Synthetic feature-level inputs only.
- No production events, personal data, credentials, tokens, IP addresses, user agents, or free-text justifications.
- Cases cover baseline, threshold boundaries, fail-closed signals, malformed schemas, advisor outages, disabled advisors, and non-enforcement.

## Intended use

- Blocking deterministic regression evaluation in pull requests.
- Comparing optional local-model advice against an authoritative deterministic baseline.
- Expanding with sanitized, human-reviewed incident patterns after privacy approval.

## Prohibited use

- Training or fine-tuning models.
- Claiming population-level accuracy, fairness, or production effectiveness.
- Treating human approval as ground truth without independent review.

## Quality gates

- Golden deterministic decisions: 100% exact match.
- Fail-closed and monotonicity invariants: 100%.
- Prompt/privacy canaries absent: 100%.
- Invalid schema acceptance: 0%.
- Golden privileged-access recommendations, reason codes, and evidence references: 100% exact match.
- Disabled, invalid-output, and unavailable model paths: 100% deterministic fallback.
- AI influence over authorization decisions: 0%.
- External model calls in default CI: 0.

## Limitations

The dataset is intentionally small and synthetic. It proves code-level invariants, not operational model quality. Optional model benchmarks require a separately versioned, privacy-reviewed dataset and human calibration.

## Governance

Changes require review of the dataset version, expected outcome, rationale, and corresponding policy or prompt version. Production-derived additions must document lawful basis, minimization, retention, and reviewer approval.
