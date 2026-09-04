"""JSON-only CLI for the admin security-lab API."""

from __future__ import annotations

import argparse
import json
import os
import sys

import httpx

from app.services.security_lab_service import UnsafeSimulationTarget, validated_target_origin


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run bounded FlowShield security simulations")
    parser.add_argument("command", choices=("list", "run", "runs"))
    parser.add_argument("scenario", nargs="?")
    parser.add_argument("--base-url", default=os.getenv("FLOW_SHIELD_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--token", default=os.getenv("FLOW_SHIELD_ADMIN_TOKEN"))
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        base_url = validated_target_origin(args.base_url)
    except UnsafeSimulationTarget as exc:
        print(json.dumps({"passed": False, "error": "unsafe_target", "detail": str(exc)}, sort_keys=True))
        return 2
    if not args.token:
        print(json.dumps({"passed": False, "error": "missing_admin_token"}, sort_keys=True))
        return 2
    if args.command == "run" and not args.scenario:
        print(json.dumps({"passed": False, "error": "scenario_required"}, sort_keys=True))
        return 2

    headers = {"Authorization": f"Bearer {args.token}"}
    path = {
        "list": "/admin/security-lab/scenarios",
        "runs": "/admin/security-lab/runs",
        "run": f"/admin/security-lab/scenarios/{args.scenario}/runs",
    }[args.command]
    try:
        with httpx.Client(base_url=base_url, headers=headers, timeout=args.timeout) as client:
            response = client.post(path, json={"seed": args.seed}) if args.command == "run" else client.get(path)
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        print(json.dumps({"passed": False, "error": "request_failed", "detail": str(exc)}, sort_keys=True))
        return 2

    print(json.dumps(payload, sort_keys=True, default=str))
    if not response.is_success:
        return 2
    if args.command == "run" and payload.get("status") != "passed":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())