#!/usr/bin/env python3
"""Fail CI when repository or GitHub Actions supply-chain policy is unsafe."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_VITE_VARIABLES = {
    "VITE_API_URL",
    "VITE_AI_ENABLED",
    "VITE_CLIENT_ID",
    "VITE_OAUTH_CLIENT_ID",
    "VITE_OAUTH_REDIRECT_URI",
    "VITE_PROXY_TARGET",
    "VITE_TEMPORAL_UI_URL",
}
FORBIDDEN_VITE_WORDS = re.compile(r"(SECRET|PASSWORD|TOKEN|PRIVATE|CREDENTIAL|API_KEY)", re.I)
FORBIDDEN_TRACKED = [
    re.compile(r"(^|/)\.env(?:\..+)?$"),
    re.compile(r"\.(?:pem|key|p12|pfx|jks|keystore|sqlite|sqlite3|db)$", re.I),
    re.compile(r"(^|/)\.dev-mailbox/"),
    re.compile(r"^backend/(?:models|guardflow_data)/"),
    re.compile(r"\.(?:onnx|pkl|pickle|joblib|pt|pth|safetensors|gguf|h5|hdf5)$", re.I),
]
TEXT_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".env", ".html"}
ACTION_USE = re.compile(r"uses:\s*([^@\s]+)@([^\s#]+)")
IMMUTABLE_SHA = re.compile(r"^[0-9a-f]{40}$")
DANGEROUS_WORKFLOW_PATTERNS = {
    "pull_request_target trigger": re.compile(r"^\s*pull_request_target\s*:", re.MULTILINE),
    "untrusted Node runtime override": re.compile(r"ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION"),
}


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, check=True, capture_output=True, text=True
    )
    return [line for line in result.stdout.splitlines() if line]


def find_forbidden_tracked_paths(paths: list[str]) -> list[str]:
    findings = []
    for path in paths:
        if path.endswith(".env.example"):
            continue
        if any(pattern.search(path) for pattern in FORBIDDEN_TRACKED):
            findings.append(path)
    return findings


def discover_vite_variables() -> set[str]:
    variables: set[str] = set()
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in {"node_modules", "dist", "build", ".git", "venv"} for part in path.parts):
            continue
        if path.suffix not in TEXT_SUFFIXES and path.name not in {"Dockerfile", "Makefile"}:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        variables.update(re.findall(r"\bVITE_[A-Z0-9_]+\b", content))
    return variables


def check_checkout_policy(relative: Path, lines: list[str]) -> list[str]:
    findings: list[str] = []
    checkout_indexes = [index for index, line in enumerate(lines) if "uses: actions/checkout@" in line]
    for index in checkout_indexes:
        indent = len(lines[index]) - len(lines[index].lstrip())
        next_step = next(
            (
                offset
                for offset, line in enumerate(lines[index + 1 :], start=index + 1)
                if line.lstrip().startswith("-") and len(line) - len(line.lstrip()) == indent
            ),
            len(lines),
        )
        block = lines[index + 1 : next_step]
        if not any(re.fullmatch(r"\s*persist-credentials:\s*false\s*", line) for line in block):
            findings.append(f"{relative}: checkout must set persist-credentials: false")
    return findings


def check_single_workflow(path: Path) -> list[str]:
    relative = path.relative_to(ROOT)
    content = path.read_text(encoding="utf-8")
    findings: list[str] = []
    if not re.search(r"^permissions:\s*\n\s{2}contents:\s*read\s*$", content, re.MULTILINE):
        findings.append(f"{relative}: top-level permissions must default to contents: read")
    findings.extend(
        f"{relative}: forbidden {label}"
        for label, pattern in DANGEROUS_WORKFLOW_PATTERNS.items()
        if pattern.search(content)
    )
    findings.extend(
        f"{relative}: {action}@{revision} is not pinned to a full commit SHA"
        for action, revision in ACTION_USE.findall(content)
        if not action.startswith("./") and not IMMUTABLE_SHA.fullmatch(revision)
    )
    findings.extend(check_checkout_policy(relative, content.splitlines()))
    return findings


def check_workflow_policy() -> list[str]:
    workflow_dir = ROOT / ".github" / "workflows"
    workflow_files = sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))
    findings: list[str] = []
    for path in workflow_files:
        findings.extend(check_single_workflow(path))

    return findings


def check_trivy_ignore_policy() -> list[str]:
    path = ROOT / ".trivyignore"
    if not path.exists():
        return []
    invalid = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
        and not line.lstrip().startswith("#")
        and not re.fullmatch(r"(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z-]+)", line.strip(), re.I)
    ]
    return [".trivyignore contains non-specific exceptions: " + ", ".join(invalid)] if invalid else []


def main() -> int:
    failures: list[str] = []
    forbidden_paths = find_forbidden_tracked_paths(tracked_files())
    if forbidden_paths:
        failures.append("Forbidden tracked paths: " + ", ".join(sorted(forbidden_paths)))

    vite_variables = discover_vite_variables()
    disallowed_vite = sorted(vite_variables - ALLOWED_VITE_VARIABLES)
    secret_shaped = sorted(name for name in vite_variables if FORBIDDEN_VITE_WORDS.search(name))
    if disallowed_vite:
        failures.append("Unapproved public Vite variables: " + ", ".join(disallowed_vite))
    if secret_shaped:
        failures.append("Secret-shaped Vite variables: " + ", ".join(secret_shaped))

    failures.extend(check_workflow_policy())
    failures.extend(check_trivy_ignore_policy())

    if failures:
        print("Repository safety policy failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("Repository safety policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
